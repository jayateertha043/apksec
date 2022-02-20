package structures

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/avast/apkverifier"
	"github.com/beevik/etree"
	"github.com/jayateertha043/apksec/pkg/colors"
)

type MetaData struct {
	Name  string
	Value string
}

type Activity struct {
	Name       string
	Permission string
	IsExported bool
}

type Application struct {
	label      string
	debuggable string
}

type Provider struct {
	Name       string
	Permission string
	IsExported bool
}

type Receiver struct {
	Name       string
	Permission string
	IsExported bool
}

type Service struct {
	Name       string
	Permission string
	IsExported bool
}

type AppInfo struct {
	Package_Name string
	Version      string
	MainActivity string
	Target_Sdk   string
	Minimum_Sdk  string
	Permissions  []string
	MetaDatas    []MetaData
	Application_ Application
	Activities   []Activity
	Providers    []Provider
	Receivers    []Receiver
	Services     []Service
	ApkHash      ApkHashes
	Cert         Certificate
}

type ApkHashes struct {
	MD5    string
	SHA1   string
	SHA256 string
}

type Certificate struct {
	Serialno           string
	Issuer             string
	Subject            string
	Sha1               string
	Sha256             string
	MD5                string
	ValidFrom          string
	ValidTo            string
	SignatureAlgorithm string
}

func (appInfo *AppInfo) InitDataFromManifest(document *etree.Document) {

	manifest := document.Copy().FindElement("//manifest")

	appInfo.Package_Name = manifest.SelectAttrValue("package", "")
	appInfo.Version = manifest.SelectAttrValue("versionName", "")

	uses_sdk := manifest.FindElement("//uses-sdk")
	appInfo.Minimum_Sdk = uses_sdk.SelectAttrValue("minSdkVersion", "")
	appInfo.Target_Sdk = uses_sdk.SelectAttrValue("targetSdkVersion", "")

	permissions := manifest.FindElements("//uses-permission")
	for _, permissionTag := range permissions {
		perm := permissionTag.SelectAttrValue("name", "")
		appInfo.Permissions = append(appInfo.Permissions, perm)
	}

	meta_datas := manifest.FindElements("//meta-data")
	for _, metaTag := range meta_datas {
		n := metaTag.SelectAttrValue("name", "")
		v := metaTag.SelectAttrValue("value", "")
		m := MetaData{Name: n, Value: v}
		appInfo.MetaDatas = append(appInfo.MetaDatas, m)
	}

	application := manifest.FindElement("//application")
	appInfo.Application_.debuggable = application.SelectAttrValue("debuggable", "false")
	appInfo.Application_.label = application.SelectAttrValue("label", "")

	main_action_tag := application.FindElement("//activity/intent-filter/action[@name='android.intent.action.MAIN']")
	main_category_tag := application.FindElement("//activity/intent-filter/category[@name='android.intent.category.LAUNCHER']")

	if main_action_tag != nil && main_category_tag != nil {
		MainActivityFromAction := "1"
		MainActivityFromCategory := "2"
		if main_action_tag.Parent().Parent().Tag == "activity" {
			MainActivityFromAction = main_action_tag.Parent().Parent().SelectAttrValue("name", "Main Action not found")
		}
		if main_category_tag.Parent().Parent().Tag == "activity" {
			MainActivityFromCategory = main_category_tag.Parent().Parent().SelectAttrValue("name", "Main Category not found")
		}
		if MainActivityFromAction == MainActivityFromCategory {
			appInfo.MainActivity = MainActivityFromAction
		}
	}
	activity_tags := manifest.FindElements("//activity")
	//isMainActivityFound := false

	for _, activity_tag := range activity_tags {
		n := activity_tag.SelectAttrValue("name", "")
		e := activity_tag.SelectAttrValue("exported", "")
		perm := activity_tag.SelectAttrValue("permission", "")
		ise := false
		if e == "true" {
			ise = true
		}

		a := Activity{Name: n, IsExported: ise, Permission: perm}
		appInfo.Activities = append(appInfo.Activities, a)
	}

	provider_tags := manifest.FindElements("//provider")

	for _, provider_tag := range provider_tags {
		n := provider_tag.SelectAttrValue("name", "")
		e := provider_tag.SelectAttrValue("exported", "")
		perm := provider_tag.SelectAttrValue("permission", "")
		ise := false
		if e == "true" {
			ise = true
		}
		p := Provider{Name: n, IsExported: ise, Permission: perm}
		appInfo.Providers = append(appInfo.Providers, p)
	}

	receiver_tags := manifest.FindElements("//receiver")
	for _, receiver_tag := range receiver_tags {
		n := receiver_tag.SelectAttrValue("name", "")
		e := receiver_tag.SelectAttrValue("exported", "")
		perm := receiver_tag.SelectAttrValue("permission", "")

		ise := false
		if e == "true" {
			ise = true
		}
		r := Receiver{Name: n, IsExported: ise, Permission: perm}
		appInfo.Receivers = append(appInfo.Receivers, r)
	}

	service_tags := manifest.FindElements("//service")
	for _, service_tag := range service_tags {
		n := service_tag.SelectAttrValue("name", "")
		e := service_tag.SelectAttrValue("exported", "")
		perm := service_tag.SelectAttrValue("permission", "")

		ise := false
		if e == "true" {
			ise = true
		}
		s := Service{Name: n, IsExported: ise, Permission: perm}
		appInfo.Services = append(appInfo.Services, s)
	}
}
func (appInfo *AppInfo) SetApkHashes(apk_path string) error {
	apkfile, err := ioutil.ReadFile(apk_path)
	if err != nil {
		return err
	}

	MD5 := md5.Sum(apkfile)
	appInfo.ApkHash.MD5 = hex.EncodeToString(MD5[:])
	Sha256 := sha256.Sum256(apkfile)
	appInfo.ApkHash.SHA256 = hex.EncodeToString(Sha256[:])
	SHA1 := sha1.Sum(apkfile)
	appInfo.ApkHash.SHA1 = hex.EncodeToString(SHA1[:])
	return nil
}

func (appInfo *AppInfo) SetCertsInfo(apk_path string) error {
	res, err := apkverifier.ExtractCerts(apk_path, nil)
	if err != nil {
		return err
	}
	cinfo, cert := apkverifier.PickBestApkCert(res)
	if cert == nil || cinfo == nil {
		return errors.New("no certs found")
	}
	cinfo.Fill(cert)
	appInfo.Cert.Serialno = cinfo.SerialNumber.String()
	appInfo.Cert.Issuer = cinfo.Issuer
	appInfo.Cert.Subject = cinfo.Subject
	appInfo.Cert.Sha1 = cinfo.Sha1
	appInfo.Cert.MD5 = cinfo.Md5
	appInfo.Cert.Sha256 = cinfo.Sha256
	appInfo.Cert.ValidFrom = cinfo.ValidFrom.String()
	appInfo.Cert.ValidTo = cinfo.ValidTo.String()
	appInfo.Cert.SignatureAlgorithm = cinfo.SignatureAlgorithm

	return nil
}

func (appInfo *AppInfo) Display() {

	fmt.Println()
	//App Info
	colors.ORANGE.Println("App Info")
	fmt.Println("--------------------------------")
	colors.CYAN.Println("\tApp Name:", appInfo.Application_.label)
	colors.CYAN.Println("\tPackage Name:", appInfo.Package_Name)
	colors.CYAN.Println("\tVersion:", appInfo.Version)
	colors.CYAN.Println("\tMain Activity:", appInfo.MainActivity)
	colors.CYAN.Println("\tTargetSdk:", appInfo.Target_Sdk)
	colors.CYAN.Println("\tMinSdk:", appInfo.Minimum_Sdk)
	if appInfo.Application_.debuggable == "true" {
		colors.RED.Println("\tDebug Enabled:", appInfo.Application_.debuggable)
	} else {
		colors.CYAN.Println("\tDebug Enabled:", appInfo.Application_.debuggable)
	}

	fmt.Println()
	//Permissions
	colors.ORANGE.Println("Permissions")
	fmt.Println("--------------------------------")
	for _, perm := range appInfo.Permissions {
		colors.CYAN.Println("\t" + perm)
	}

	fmt.Println()
	//Meta-Data
	colors.ORANGE.Println("Meta-Data")
	fmt.Println("--------------------------------")
	for _, metadata := range appInfo.MetaDatas {
		colors.CYAN.Println("\t" + metadata.Name + ": " + metadata.Value)
	}

	fmt.Println()
	//Activities
	colors.ORANGE.Println("Activities")
	fmt.Println("--------------------------------")
	for _, activity := range appInfo.Activities {
		fmt.Println()
		if activity.IsExported && activity.Permission == "" {
			colors.RED.Println("\tName" + ": " + activity.Name)
			colors.RED.Println("\t" + "Exported: " + strconv.FormatBool(activity.IsExported))
		} else {
			colors.CYAN.Println("\tName" + ": " + activity.Name)
			colors.CYAN.Println("\t" + "Exported: " + strconv.FormatBool(activity.IsExported))

		}
	}

	fmt.Println()
	//Content Providers
	colors.ORANGE.Println("Content Providers")
	fmt.Println("--------------------------------")
	for _, provider := range appInfo.Providers {
		fmt.Println()
		if provider.IsExported && provider.Permission == "" {
			colors.RED.Println("\tName" + ": " + provider.Name)
			colors.RED.Println("\t" + "Exported: " + strconv.FormatBool(provider.IsExported))
		} else {
			colors.CYAN.Println("\tName" + ": " + provider.Name)
			colors.CYAN.Println("\t" + "Exported: " + ": " + strconv.FormatBool(provider.IsExported))
		}
	}

	fmt.Println()
	//Broadcast Receivers
	colors.ORANGE.Println("Broadcast Receivers")
	fmt.Println("--------------------------------")
	for _, receiver := range appInfo.Receivers {
		fmt.Println()
		if receiver.IsExported && receiver.Permission == "" {
			colors.RED.Println("\tName" + ": " + receiver.Name)
			colors.RED.Println("\t" + "Exported: " + strconv.FormatBool(receiver.IsExported))
		} else {
			colors.CYAN.Println("\tName" + ": " + receiver.Name)
			colors.CYAN.Println("\t" + "Exported: " + ": " + strconv.FormatBool(receiver.IsExported))
		}
	}

	fmt.Println()
	//Services
	colors.ORANGE.Println("Services")
	fmt.Println("--------------------------------")
	for _, service := range appInfo.Services {
		fmt.Println()
		if service.IsExported && service.Permission == "" {
			colors.RED.Println("\tName" + ": " + service.Name)
			colors.RED.Println("\t" + "Exported: " + strconv.FormatBool(service.IsExported))
		} else {
			colors.CYAN.Println("\tName" + ": " + service.Name)
			colors.CYAN.Println("\t" + "Exported: " + ": " + strconv.FormatBool(service.IsExported))
		}
	}

	//Hashes
	fmt.Println()
	colors.ORANGE.Println("Hashes")
	fmt.Println("--------------------------------")
	colors.CYAN.Println("\tMD5" + ": " + appInfo.ApkHash.MD5)
	colors.CYAN.Println("\tSHA1" + ": " + appInfo.ApkHash.SHA1)
	colors.CYAN.Println("\tSHA256" + ": " + appInfo.ApkHash.SHA256)

	//Certificates
	fmt.Println()
	colors.ORANGE.Println("Certificates")
	fmt.Println("--------------------------------")
	colors.CYAN.Println("\tSerial No: " + appInfo.Cert.Serialno)
	colors.CYAN.Println("\tIssuer: " + appInfo.Cert.Issuer)
	colors.CYAN.Println("\tSubject: " + appInfo.Cert.Subject)
	colors.CYAN.Println("\tValid From: " + appInfo.Cert.ValidFrom)
	colors.CYAN.Println("\tValid To: " + appInfo.Cert.ValidTo)
	colors.CYAN.Println("\tMD5: " + appInfo.Cert.MD5)
	colors.CYAN.Println("\tSHA1: " + appInfo.Cert.Sha1)
	colors.CYAN.Println("\tSHA256: " + appInfo.Cert.Sha256)
	colors.CYAN.Println("\tSignature Algorithm: " + appInfo.Cert.SignatureAlgorithm)

}
