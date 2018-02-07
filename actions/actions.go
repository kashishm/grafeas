package actions

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	pb "github.com/kashishm/grafeas/proto"
	"google.golang.org/grpc"
)

const attestation = "attestation"

func Project(name string, conn *grpc.ClientConn) error {
	pClient := pb.NewGrafeasProjectsClient(conn)
	_, err := pClient.GetProject(context.Background(), &pb.GetProjectRequest{Name: "projects/" + name})
	if err == nil {
		return nil
	}
	_, err = pClient.CreateProject(
		context.Background(),
		&pb.CreateProjectRequest{
			Name: "projects/" + name,
		},
	)
	return err
}

func Note(client pb.GrafeasClient, name, kind, project string) error {
	name = "projects/" + project + "/notes/" + name
	if _, err := client.GetNote(context.Background(), &pb.GetNoteRequest{Name: name}); err == nil {
		return nil
	}
	_, err := client.CreateNote(
		context.Background(),
		&pb.CreateNoteRequest{
			NoteId: name,
			Parent: project,
			Note: &pb.Note{
				Name: name,
				Kind: pb.Note_Kind(pb.Note_Kind_value[kind]),
			},
		})
	return err
}

func ImageOccurrence(client pb.GrafeasClient, project, name, base, url string) error {
	if err := Note(client, base, "Note_IMAGE_BASIS", project); err != nil {
		return err
	}
	_, err := client.CreateOccurrence(
		context.Background(),
		&pb.CreateOccurrenceRequest{
			Parent: "projects/" + project,
			Occurrence: &pb.Occurrence{
				Name:        "projects/" + project + "/occurrences/" + name,
				NoteName:    "projects/" + project + "/notes/" + base,
				ResourceUrl: url,
				Kind:        pb.Note_IMAGE_BASIS,
			},
		},
	)
	return err
}

func Authority(conn *grpc.ClientConn, client pb.GrafeasClient, name string, keys []string) error {
	if err := Project(attestation, conn); err != nil {
		return err
	}
	noteName := "projects/" + attestation + "/notes/" + name
	_, err := client.CreateNote(
		context.Background(),
		&pb.CreateNoteRequest{
			NoteId: noteName,
			Parent: attestation,
			Note: &pb.Note{
				Name: noteName,
				Kind: pb.Note_ATTESTATION,
				NoteType: &pb.Note_AttestationType{
					AttestationType: &pb.AttestationAuthority{
						Hint: &pb.AttestationAuthority_AttestationAuthorityHint{
							HumanReadableName: name,
							Keys:              keys,
						},
					},
				},
			},
		})
	return err
}

func AttestationOccurrence(client pb.GrafeasClient, project, occurrence, note, url, keyID, sigFile string) error {
	bytes, err := ioutil.ReadFile(sigFile)
	if err != nil {
		return err
	}
	note = "projects/attestation/notes/" + note
	_, err = client.CreateOccurrence(
		context.Background(),
		&pb.CreateOccurrenceRequest{
			Parent: "projects/" + project,
			Occurrence: &pb.Occurrence{
				Name:        "projects/" + project + "/occurrences/" + occurrence,
				NoteName:    note,
				ResourceUrl: url,
				Kind:        pb.Note_ATTESTATION,
				Details: &pb.Occurrence_AttestationDetails{
					AttestationDetails: &pb.AttestationAuthority_Attestation{
						Signature: &pb.AttestationAuthority_Attestation_PgpSignedAttestation{
							PgpSignedAttestation: &pb.PgpSignedAttestation{
								KeyId:     &pb.PgpSignedAttestation_PgpKeyId{PgpKeyId: keyID},
								Signature: string(bytes),
							},
						},
					},
				},
			},
		},
	)
	return err
}

func VerifyResource(client pb.GrafeasClient, project, occuerrence, url string) error {
	o, err := FilterOccurrencies(client, url, project, "ATTESTATION")
	if err != nil {
		return err
	}
	if len(o) > 0 {
		sign := o[0].GetAttestationDetails().GetPgpSignedAttestation().GetSignature()
		key := o[0].GetAttestationDetails().GetPgpSignedAttestation().GetPgpKeyId()
		n, err := client.GetOccurrenceNote(context.Background(), &pb.GetOccurrenceNoteRequest{
			Name: "projects/" + project + "/occurrences/" + occuerrence,
		})
		if err != nil {
			return err
		}
		valid := false
		for _, k := range n.GetAttestationType().GetHint().GetKeys() {
			if k == key {
				valid = true
			}
		}
		if !valid {
			return err
		}

		content := []byte(sign)
		tmpfile, err := ioutil.TempFile("", "example")
		if err != nil {
			return err
		}
		defer os.Remove(tmpfile.Name())
		if _, err := tmpfile.Write(content); err != nil {
			return err
		}

		cmd := exec.Command("gpg", "--keyserver-options", "no-auto-key-retrieve", "--decrypt", tmpfile.Name())
		output, err := cmd.Output()
		if err != nil {
			return err
		}
		if strings.TrimSpace(strings.Split(string(output), "\n")[0]) != o[0].GetResourceUrl() {
			return errors.New("Invalid sign")
		}
		return nil
	}
	return errors.New("Invalid sign")
}

func BuildOccurrence(client pb.GrafeasClient, project, occurrence, note, url, buildID, artifactName, creator string) error {
	_, err := client.CreateOccurrence(
		context.Background(),
		&pb.CreateOccurrenceRequest{
			Parent: "projects/" + project,
			Occurrence: &pb.Occurrence{
				Name:        "projects/" + project + "/occurrences/" + occurrence,
				NoteName:    note,
				ResourceUrl: url,
				Kind:        pb.Note_BUILD_DETAILS,
				Details: &pb.Occurrence_BuildDetails{
					BuildDetails: &pb.BuildDetails{
						Provenance: &pb.BuildProvenance{
							Id:             buildID,
							ProjectId:      project,
							BuiltArtifacts: []*pb.Artifact{{Name: artifactName}},
							Creator:        creator,
						},
					},
				},
			},
		},
	)
	return err
}

type vulnerability struct {
	Name      string
	Severity  string
	CvssScore string
}
type dependency struct {
	Vulnerabilities []vulnerability
}
type scanInfo struct {
	Dependencies []dependency
}

type iVulnerability struct {
	Vulnerability string
	Featurename   string
	Severity      string
}
type iScanInfo struct {
	image           string
	Vulnerabilities []iVulnerability
}

func ImageVulnerabilityOccurrence(client pb.GrafeasClient, project, storeProject, url, jsonFile string) (errs []error) {
	bytes, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		return []error{err}
	}
	var si iScanInfo
	if err = json.Unmarshal(bytes, &si); err != nil {
		return []error{err}
	}
	for _, v := range si.Vulnerabilities {
		if err = Note(client, v.Vulnerability, "PACKAGE_VULNERABILITY", storeProject); err != nil {
			errs = append(errs, err)
			continue
		}
		_, err = client.CreateOccurrence(
			context.Background(),
			&pb.CreateOccurrenceRequest{
				Parent: "projects/" + project,
				Occurrence: &pb.Occurrence{
					Name:        "projects/" + project + "/occurrences/" + v.Featurename + "_" + v.Vulnerability,
					NoteName:    "projects/" + storeProject + "/notes/" + v.Vulnerability,
					ResourceUrl: url,
					Kind:        pb.Note_PACKAGE_VULNERABILITY,
					Details: &pb.Occurrence_VulnerabilityDetails{
						VulnerabilityDetails: &pb.VulnerabilityType_VulnerabilityDetails{
							Severity: pb.VulnerabilityType_HIGH,
						},
					},
				},
			},
		)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return
}

func PythonVulnerabilityOccurrence(client pb.GrafeasClient, project, storeProject, url, jsonFile string) (errs []error) {
	bytes, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		return []error{err}
	}
	var vulnerabilities [][]string
	if err = json.Unmarshal(bytes, &vulnerabilities); err != nil {
		return []error{err}
	}
	for _, v := range vulnerabilities {
		if err = Note(client, v[4], "PACKAGE_VULNERABILITY", storeProject); err != nil {
			errs = append(errs, err)
			continue
		}
		_, err = client.CreateOccurrence(
			context.Background(),
			&pb.CreateOccurrenceRequest{
				Parent: "projects/" + project,
				Occurrence: &pb.Occurrence{
					Name:        "projects/" + project + "/occurrences/" + v[0],
					NoteName:    "projects/" + storeProject + "/notes/" + v[4],
					ResourceUrl: url,
					Kind:        pb.Note_PACKAGE_VULNERABILITY,
					Details: &pb.Occurrence_VulnerabilityDetails{
						VulnerabilityDetails: &pb.VulnerabilityType_VulnerabilityDetails{
							Severity: pb.VulnerabilityType_HIGH,
						},
					},
				},
			},
		)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return
}

func VulnerabilityOccurrence(client pb.GrafeasClient, project, storeProject, url, jsonFile string) (errs []error) {
	bytes, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		return []error{err}
	}
	var si scanInfo
	if err = json.Unmarshal(bytes, &si); err != nil {
		return []error{err}
	}
	for _, d := range si.Dependencies {
		for _, v := range d.Vulnerabilities {
			if err = Note(client, v.Name, "PACKAGE_VULNERABILITY", storeProject); err != nil {
				errs = append(errs, err)
				continue
			}
			cvssScore, err := strconv.ParseFloat(v.CvssScore, 32)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			_, err = client.CreateOccurrence(
				context.Background(),
				&pb.CreateOccurrenceRequest{
					Parent: "projects/" + project,
					Occurrence: &pb.Occurrence{
						Name:        "projects/" + project + "/occurrences/" + v.Name,
						NoteName:    "projects/" + storeProject + "/notes/" + v.Name,
						ResourceUrl: url,
						Kind:        pb.Note_PACKAGE_VULNERABILITY,
						Details: &pb.Occurrence_VulnerabilityDetails{
							VulnerabilityDetails: &pb.VulnerabilityType_VulnerabilityDetails{
								Severity:  pb.VulnerabilityType_Severity(pb.VulnerabilityType_Severity_value[v.Severity]),
								CvssScore: float32(cvssScore),
							},
						},
					},
				},
			)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return
}

func FilterOccurrencies(client pb.GrafeasClient, resource, project, kind string) (occurrencies []*pb.Occurrence, e error) {
	resp, err := client.ListOccurrences(
		context.Background(),
		&pb.ListOccurrencesRequest{
			Parent: "projects/" + project,
		},
	)
	if err != nil {
		return nil, err
	}
	for _, o := range resp.Occurrences {
		if o.ResourceUrl == resource && o.Kind == pb.Note_Kind(pb.Note_Kind_value[kind]) {
			occurrencies = append(occurrencies, o)
		}
	}
	return occurrencies, nil
}
