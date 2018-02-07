package main

import (
	"fmt"
	"os"

	"github.com/kashishm/grafeas/actions"
	pb "github.com/kashishm/grafeas/proto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var (
	project      string
	artifactURL  string
	grafeasURL   string
	note         string
	occurrence   string
	kind         string
	issues       bool
	buildID      string
	artifactName string
	creator      string
	severity     string
	packageType  string
	name         string
	keys         []string
	key          string
	sig          string
	jsonFile     string
	store        string
	base         string
	verify       bool
	python       bool
	image        bool
	conn         *grpc.ClientConn
	err          error
	client       pb.GrafeasClient
	rootCmd      = &cobra.Command{
		Use: "grafeas",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			conn, err = grpc.Dial(grafeasURL, grpc.WithInsecure())
			if err != nil {
				fatal(err)
			}
			client = pb.NewGrafeasClient(conn)
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Usage()
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			conn.Close()
		},
	}
	projectCmd = &cobra.Command{
		Use:   "project",
		Short: "Create Grafeas project",
		Run: func(cmd *cobra.Command, args []string) {
			if err = actions.Project(project, conn); err != nil {
				fatal(err)
			}
		},
	}
	noteCmd = &cobra.Command{
		Use:   "note",
		Short: "Create Grafeas note",
		Run: func(cmd *cobra.Command, args []string) {
			if err = actions.Note(client, note, kind, project); err != nil {
				fatal(err)
			}
		},
	}
	occurrenceCmd = &cobra.Command{
		Use:   "occurrence",
		Short: "Create Grafeas occurrence",
		Run: func(cmd *cobra.Command, args []string) {
			if issues {
				o, err := actions.FilterOccurrencies(client, artifactURL, project, "PACKAGE_VULNERABILITY")
				if err != nil {
					fatal(err)
				}
				if len(o) > 0 {
					fmt.Printf("✘ [FAIL] Following vulnerabilities found\n\n%v\n", o)
					os.Exit(1)
				}
				fmt.Println("✔ [PASS] No vulnerabilities found")
			}
		},
	}
	buildOccurrenceCmd = &cobra.Command{
		Use:   "build",
		Short: "Create Grafeas build occurrence",
		Run: func(cmd *cobra.Command, args []string) {
			if err = actions.BuildOccurrence(client, project, occurrence, note, artifactURL, buildID, artifactName, creator); err != nil {
				fatal(err)
			}
		},
	}
	imageOccurrenceCmd = &cobra.Command{
		Use:   "image",
		Short: "Create Grafeas image occurrence",
		Run: func(cmd *cobra.Command, args []string) {
			if err = actions.ImageOccurrence(client, project, name, base, artifactURL); err != nil {
				fatal(err)
			}
		},
	}
	vulnerabilityOccurrenceCmd = &cobra.Command{
		Use:   "vulnerability",
		Short: "Create Grafeas vulnerability occurrence",
		Run: func(cmd *cobra.Command, args []string) {
			if image {
				if errs := actions.ImageVulnerabilityOccurrence(client, project, store, artifactURL, jsonFile); len(errs) > 0 {
					fatal(errs)
				}
			} else if python {
				if errs := actions.PythonVulnerabilityOccurrence(client, project, store, artifactURL, jsonFile); len(errs) > 0 {
					fatal(errs)
				}
			} else if errs := actions.VulnerabilityOccurrence(client, project, store, artifactURL, jsonFile); len(errs) > 0 {
				fatal(errs)
			}
		},
	}
	attestationOccurrenceCmd = &cobra.Command{
		Use:   "attestation",
		Short: "Create or verify Grafeas attestation occurrence",
		Run: func(cmd *cobra.Command, args []string) {
			if verify {
				if err = actions.VerifyResource(client, project, occurrence, artifactURL); err != nil {
					fatal("✘ [FAIL] " + occurrence + " : Not found for resource with url " + artifactURL)
				}
				fmt.Println("✔ [PASS] " + occurrence + " : Verified")
			} else if err = actions.AttestationOccurrence(client, project, occurrence, note, artifactURL, key, sig); err != nil {
				fatal(err)
			}
		},
	}
	authorityCmd = &cobra.Command{
		Use:   "authority",
		Short: "Create Grafeas attestation authority which can attest resources",
		Run: func(cmd *cobra.Command, args []string) {
			if err = actions.Authority(conn, client, name, keys); err != nil {
				fatal(err)
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&grafeasURL, "url", "u", "localhost:10000", "Grafeas server URL")

	projectCmd.Flags().StringVarP(&project, "project", "p", "", "Project name")

	noteCmd.Flags().StringVarP(&note, "note", "n", "", "Note name")
	noteCmd.Flags().StringVarP(&kind, "kind", "k", "KIND_UNSPECIFIED", "Note kinds(KIND_UNSPECIFIED, PACKAGE_VULNERABILITY, BUILD_DETAILS, IMAGE_BASIS, PACKAGE_MANAGER, DEPLOYABLE, DISCOVERY)")
	noteCmd.Flags().StringVarP(&project, "project", "p", "", "Project name")

	occurrenceCmd.PersistentFlags().StringVarP(&project, "project", "p", "", "Project name")
	occurrenceCmd.PersistentFlags().StringVarP(&artifactURL, "artifactURL", "a", "", "Artifact name")
	occurrenceCmd.Flags().BoolVarP(&issues, "issues", "i", false, "Issues reported in arifact")

	buildOccurrenceCmd.Flags().StringVarP(&occurrence, "occurrence", "o", "", "Occurrence name")
	buildOccurrenceCmd.Flags().StringVarP(&note, "note", "n", "", "Note name")
	buildOccurrenceCmd.Flags().StringVarP(&buildID, "build-id", "b", "", "Unique build ID")
	buildOccurrenceCmd.Flags().StringVarP(&artifactName, "name", "e", "", "Artifact name")
	buildOccurrenceCmd.Flags().StringVarP(&creator, "creator", "c", "", "Creator email")
	occurrenceCmd.AddCommand(buildOccurrenceCmd)

	imageOccurrenceCmd.Flags().StringVarP(&name, "name", "n", "", "Image name")
	imageOccurrenceCmd.Flags().StringVarP(&base, "base", "b", "", "Base image name")
	occurrenceCmd.AddCommand(imageOccurrenceCmd)

	vulnerabilityOccurrenceCmd.Flags().StringVarP(&jsonFile, "json", "j", "", "Path to json file with info")
	vulnerabilityOccurrenceCmd.Flags().StringVarP(&store, "store", "s", "", "Vulnerability store name")
	vulnerabilityOccurrenceCmd.Flags().BoolVar(&python, "python", false, "Python package vulnerability type")
	vulnerabilityOccurrenceCmd.Flags().BoolVar(&image, "image", false, "Image package vulnerability type")
	occurrenceCmd.AddCommand(vulnerabilityOccurrenceCmd)

	attestationOccurrenceCmd.Flags().StringVarP(&occurrence, "occurrence", "o", "", "Occurrence name")
	attestationOccurrenceCmd.Flags().StringVarP(&note, "note", "n", "", "Note name")
	attestationOccurrenceCmd.Flags().StringVarP(&key, "key", "k", "", "Public key ID")
	attestationOccurrenceCmd.Flags().StringVarP(&sig, "signature", "s", "", "Path to signature")
	attestationOccurrenceCmd.Flags().BoolVarP(&verify, "verify", "v", false, "Verify signature")
	occurrenceCmd.AddCommand(attestationOccurrenceCmd)

	authorityCmd.Flags().StringVarP(&name, "name", "n", "", "Attestation authority name")
	authorityCmd.Flags().StringSliceVarP(&keys, "keys", "k", keys, "Attestation authority public keys")
	authorityCmd.Flags().StringVarP(&project, "project", "p", "", "Project name")

	rootCmd.AddCommand(projectCmd, noteCmd, occurrenceCmd, authorityCmd)
}

func fatal(v interface{}) {
	fmt.Println(v)
	conn.Close()
	os.Exit(1)
}

func main() {
	rootCmd.Execute()
}
