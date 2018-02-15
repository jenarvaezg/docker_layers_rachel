package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/heroku/docker-registry-client/registry"
	digest "github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
)

const (
	rachelReviewURL        = "https://rachelanalyzer.com/api/review" // image=abc:123
	rachelStatusInProgress = "inProgress"
	rachelStatusFinished   = "finished"
	rachesStatusNotFound   = "Image not found"
	resultsFile            = ".results.json"
)

type vulnerabilityDetail struct {
	Description       string `json:"cve_desc"`
	FixedVersion      string `json:"cve_fixed_version"`
	CVELink           string `json:"cve_link"`
	CVEName           string `json:"cve_name"`
	CVESeverityNumber int    `json:"cve_severity_nr"`
	InstalledVersion  string `json:"installed_version"`
	NamespaceName     string `json:"namespace_name"`
	PackageName       string `json:"package_name"`
}

type rachelReview struct {
	MyVulns []vulnerabilityDetail `json:"my_vulns"`
	Detail  []vulnerabilityDetail `json:"detail"`
	ID      string                `json:"_id"`
	Image   string                `json:"image"`
	Status  string                `json:"status"`
}

func debug(format string, args ...interface{}) {
	if verbose {
		log.Printf(format, args...)
	}
}

func (r rachelReview) save(layers []digest.Digest) {
	reviews[getLayersChainID(layers)] = r
	saveReviews()
}

func (r *rachelReview) removeParentVulns(parent rachelReview) {
	r.MyVulns = []vulnerabilityDetail{}
	debug("Removing vulns from base")
	for _, vuln := range r.Detail {
		if !isVulnInParent(vuln, parent.Detail) {
			debug("%s is not in parent", vuln.CVEName)
			r.MyVulns = append(r.MyVulns, vuln)
		}
	}
}

func (r rachelReview) printMyVulns() {
	s := fmt.Sprintf("Vulnerabilities for image %s", r.Image)
	if ignoreBase {
		s += " (Ignoring base vulnerabilities)"
	}
	s += "\n\n======================================================================\n"

	jsonBytes, err := json.MarshalIndent(r.MyVulns, "", "  ")
	if err != nil {
		fail(err)
	}
	s += string(jsonBytes[:]) + "\n"

	fmt.Println(s)

}

func isVulnInParent(vuln vulnerabilityDetail, parentVulns []vulnerabilityDetail) bool {
	for _, parentVuln := range parentVulns {
		if vuln == parentVuln {
			return true
		}
	}
	return false
}

var reviews map[digest.Digest]rachelReview

var verbose, ignoreBase bool

var scanCmd = &cobra.Command{
	Use:   "scan [image]",
	Short: "Scan image using rachel analyzer",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		loadReviews()
		imageName := args[0]
		repository, tag := getRepoAndTagFromImageName(imageName)
		layers := getImageLayers(repository, tag)
		review := scanImage(imageName)
		if ignoreBase {
			parentReview, err := getParent(layers)
			if err == nil {
				review.removeParentVulns(parentReview)
			}
		}
		review.save(layers)
		review.printMyVulns()
	},
}

func init() {
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	scanCmd.Flags().BoolVarP(&ignoreBase, "ignoreBase", "i", false, "Try to ignore base vulnerabilities if base image is found")
	rootCmd.AddCommand(scanCmd)
}

func getLayersChainID(layers []digest.Digest) digest.Digest {
	var xoredBytes []byte
	for layerPos, layer := range layers {
		bytes, err := hex.DecodeString(layer.Encoded())
		if err != nil {
			fail(err)
		}

		if layerPos == 0 {
			xoredBytes = bytes
		} else {
			for i := range bytes {
				xoredBytes[i] = xoredBytes[i] ^ bytes[i]
			}
		}
	}

	return digest.NewDigestFromBytes(digest.SHA256, xoredBytes)
}

func loadReviews() {
	debug("Loading previous reviews for base-detection\n")
	reviews = make(map[digest.Digest]rachelReview)

	raw, err := ioutil.ReadFile(resultsFile)
	if err != nil {
		f, err := os.OpenFile(resultsFile, os.O_RDONLY|os.O_CREATE, 0666)
		if err != nil {
			fail(err)
		}
		f.Close()
		return
	}

	json.Unmarshal(raw, &reviews)
	debug("Found %d reviews\n", len(reviews))
}

func saveReviews() {
	debug("Saving reviews for base-detection\n")
	jsonBytes, err := json.MarshalIndent(reviews, "", "  ")
	if err != nil {
		fail(err)
	}

	err = ioutil.WriteFile(resultsFile, jsonBytes, 0644)
	if err != nil {
		fail(err)
	}
	debug("Reviews saved succesfully\n")
}

func getRepoAndTagFromImageName(imageName string) (string, string) {
	debug("Loading previous reviews for base-detection\n")
	if strings.Contains(imageName, ":") {
		splitted := strings.Split(imageName, ":")
		return splitted[0], splitted[1]
	}
	debug("Tag not provided, setting tag as latest\n")
	return imageName, "latest"
}

func getImageLayers(repository, tag string) (layers []digest.Digest) {
	debug("Fetching layers for this image\n")
	url := "https://registry.hub.docker.com"
	username := "" // anonymous
	password := "" // anonymous
	hub, err := registry.New(url, username, password)
	if !verbose {
		hub.Logf = registry.Quiet
	}

	if err != nil {
		fail(err)
	}

	if !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}
	manifest, err := hub.ManifestV2(repository, tag)
	if err != nil {
		fail(err)
	}

	for _, layer := range manifest.Layers {
		layers = append(layers, layer.Digest)
	}

	debug("Got %d layers for this image\n", len(layers))
	return layers
}

func getParent(layers []digest.Digest) (rachelReview, error) {
	//ignore first layer because that is CMD/ENTRYPOINT, go from upper to lower layers looking for a review
	for i := len(layers) - 1; i >= 0; i-- {
		debug("Looking for %d layers match for parent", i+1)
		subChainID := getLayersChainID(layers[:i])
		if parent, ok := reviews[subChainID]; ok {
			fmt.Println("Found parent:", parent.Image)
			return parent, nil
		}
	}
	fmt.Println("No parent found for this image")
	return rachelReview{}, nil
}

func scanImage(image string) (review rachelReview) {

	debug("Fetching review")
	for review.Status = rachelStatusInProgress; review.Status == rachelStatusInProgress; {
		r, err := http.Get(fmt.Sprintf("%s?image=%s", rachelReviewURL, image))
		if err != nil {
			fail(err)
		}
		defer r.Body.Close()

		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			fail(err)
		}

		if review.Status == rachelStatusInProgress {
			debug("Polling for review\n")
			time.Sleep(time.Second * 2)
		}
	}
	review.MyVulns = review.Detail

	return review

}
