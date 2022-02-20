package vt

import (
	"fmt"
	"log"

	"github.com/VirusTotal/vt-go"
	"github.com/jayateertha043/apksec/pkg/colors"
)

func DisplayVTResults(apiKey string, hash string) {
	client := vt.NewClient(apiKey)
	file, err := client.GetObject(vt.URL("files/" + hash))
	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()
	colors.ORANGE.Println("VirusTotal Results")
	fmt.Println("--------------------------------")
	type_extension, err := file.Get("type_extension")
	if err == nil {
		colors.CYAN.Println("\tType Extension:", type_extension)
	}

	fmd, err := file.GetTime("first_submission_date")
	if err == nil {
		colors.CYAN.Println("\tFirst Submitted On:", fmd)
	}

	lmd, err := file.GetTime("last_submission_date")
	if err == nil {
		colors.CYAN.Println("\tLast Submitted On:", lmd)
	}

	total_submission, err := file.GetTime("times_submitted")
	if err == nil {
		colors.CYAN.Println("\tTimes Submitted:", total_submission)
	}

	size, err := file.Get("size")
	if err == nil {
		colors.CYAN.Println("\tSize:", size, "Bytes")
	}
	reputation, err := file.GetInt64("reputation")
	if err == nil {
		if reputation < 0 {
			colors.RED.Println("\tCommunity Reputation:", reputation, "(malicious)")
		} else if reputation > 0 {
			colors.CYAN.Println("\tCommunity Reputation: ", reputation, "(harmless)")
		} else {
			colors.CYAN.Println("\tCommunity Reputation:", reputation, " not available")

		}
		colors.CYAN.Println("\tType Extension:", type_extension)
	}
	total_votes, err := file.Get("total_votes")
	if err == nil {
		colors.CYAN.Println("\tVotes:")
		if total_votes_map := total_votes.(map[string]interface{}); total_votes_map != nil {
			for k, v := range total_votes_map {
				colors.CYAN.Println("\t\t", k, ":", v)

			}
		}

	}

	ptc, err := file.Get("popular_threat_classification")
	if err == nil {
		if ptc_map := ptc.(map[string]interface{}); ptc_map != nil {
			colors.CYAN.Println("\tSuggested Threat Label: ", ptc_map["suggested_threat_label"])
		}
	}

	las, err := file.Get("last_analysis_stats")
	if err == nil {
		if las_map := las.(map[string]interface{}); las_map != nil {
			colors.CYAN.Println("\tLast Analysis Stats:")
			for k, v := range las_map {
				colors.CYAN.Println("\t\t", k, ":", v)

			}

		}
	}

}
