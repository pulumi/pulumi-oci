// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"fmt"

	"github.com/blang/semver"
	"github.com/pulumi/pulumi-oci/sdk/go/oci"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type module struct {
	version semver.Version
}

func (m *module) Version() semver.Version {
	return m.version
}

func (m *module) Construct(ctx *pulumi.Context, name, typ, urn string) (r pulumi.Resource, err error) {
	switch typ {
	case "oci:LogAnalytics/logAnalyticsEntity:LogAnalyticsEntity":
		r = &LogAnalyticsEntity{}
	case "oci:LogAnalytics/logAnalyticsImportCustomContent:LogAnalyticsImportCustomContent":
		r = &LogAnalyticsImportCustomContent{}
	case "oci:LogAnalytics/logAnalyticsLogGroup:LogAnalyticsLogGroup":
		r = &LogAnalyticsLogGroup{}
	case "oci:LogAnalytics/logAnalyticsObjectCollectionRule:LogAnalyticsObjectCollectionRule":
		r = &LogAnalyticsObjectCollectionRule{}
	case "oci:LogAnalytics/logAnalyticsPreferencesManagement:LogAnalyticsPreferencesManagement":
		r = &LogAnalyticsPreferencesManagement{}
	case "oci:LogAnalytics/logAnalyticsResourceCategoriesManagement:LogAnalyticsResourceCategoriesManagement":
		r = &LogAnalyticsResourceCategoriesManagement{}
	case "oci:LogAnalytics/logAnalyticsUnprocessedDataBucketManagement:LogAnalyticsUnprocessedDataBucketManagement":
		r = &LogAnalyticsUnprocessedDataBucketManagement{}
	case "oci:LogAnalytics/namespace:Namespace":
		r = &Namespace{}
	case "oci:LogAnalytics/namespaceScheduledTask:NamespaceScheduledTask":
		r = &NamespaceScheduledTask{}
	default:
		return nil, fmt.Errorf("unknown resource type: %s", typ)
	}

	err = ctx.RegisterResource(typ, name, nil, r, pulumi.URN_(urn))
	return
}

func init() {
	version, err := oci.PkgVersion()
	if err != nil {
		version = semver.Version{Major: 1}
	}
	pulumi.RegisterResourceModule(
		"oci",
		"LogAnalytics/logAnalyticsEntity",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"LogAnalytics/logAnalyticsImportCustomContent",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"LogAnalytics/logAnalyticsLogGroup",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"LogAnalytics/logAnalyticsObjectCollectionRule",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"LogAnalytics/logAnalyticsPreferencesManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"LogAnalytics/logAnalyticsResourceCategoriesManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"LogAnalytics/logAnalyticsUnprocessedDataBucketManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"LogAnalytics/namespace",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"LogAnalytics/namespaceScheduledTask",
		&module{version},
	)
}