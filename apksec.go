package main

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"strings"

	"github.com/avast/apkparser"
	"github.com/beevik/etree"
	"github.com/jayateertha043/apksec/pkg/colors"
	"github.com/jayateertha043/apksec/pkg/structures"
	"github.com/jayateertha043/apksec/pkg/vt"
)

func main() {

	apk_path := flag.String("apk", "", "apk path")
	vt_api := flag.String("vt", "", "VirusTotal api key")
	flag.Parse()

	printBanner()

	if !strings.HasSuffix(*apk_path, ".apk") {
		panic("Invalid apk provided")
	}

	w := &bytes.Buffer{}
	enc := xml.NewEncoder(w)
	enc.Indent("", "    ")
	apkReader, err := apkparser.OpenZip(*apk_path)
	if err != nil {
		panic("\nFailed reading apk: " + err.Error())
	}
	defer apkReader.Close()

	parser, reserr := apkparser.NewParser(apkReader, enc)
	if reserr != nil {
		panic("\nFailed to parse resources:" + reserr.Error())

	}

	err = parser.ParseXml("AndroidManifest.xml")

	fmt.Println()
	if err != nil {
		panic("\nFailed to parse AndroidManifest.xml:" + err.Error())

	}

	var appInfo structures.AppInfo
	doc := etree.NewDocument()
	doc.ReadFromBytes(w.Bytes())
	appInfo.InitDataFromManifest(doc)
	appInfo.SetApkHashes(*apk_path)
	appInfo.SetCertsInfo(*apk_path)

	appInfo.Display()
	if *vt_api != "" && appInfo.ApkHash.SHA256 != "" {
		vt.DisplayVTResults(*vt_api, appInfo.ApkHash.MD5)
	}

}

func printBanner() {
	var Banner string = `
	 █████╗ ██████╗ ██╗  ██╗███████╗███████╗ ██████╗
	██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔════╝
	███████║██████╔╝█████╔╝ ███████╗█████╗  ██║     
	██╔══██║██╔═══╝ ██╔═██╗ ╚════██║██╔══╝  ██║     
	██║  ██║██║     ██║  ██╗███████║███████╗╚██████╗
	╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
													`
	colors.GREEN.Println(Banner)

}
