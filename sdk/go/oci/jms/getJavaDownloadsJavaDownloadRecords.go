// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package jms

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Java Download Records in Oracle Cloud Infrastructure Jms Java Downloads service.
//
// Returns a list of Java download records in a tenancy based on specified parameters.
// See [JavaReleases API](https://docs.cloud.oracle.com/iaas/api/#/en/jms/20210610/JavaRelease/ListJavaReleases)
// for possible values of `javaFamilyVersion` and `javaReleaseVersion` parameters.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/jms"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := jms.GetJavaDownloadsJavaDownloadRecords(ctx, &jms.GetJavaDownloadsJavaDownloadRecordsArgs{
//				CompartmentId:     compartmentId,
//				Architecture:      pulumi.StringRef(javaDownloadRecordArchitecture),
//				FamilyVersion:     pulumi.StringRef(javaDownloadRecordFamilyVersion),
//				OsFamily:          pulumi.StringRef(javaDownloadRecordOsFamily),
//				PackageTypeDetail: pulumi.StringRef(javaDownloadRecordPackageTypeDetail),
//				ReleaseVersion:    pulumi.StringRef(javaDownloadRecordReleaseVersion),
//				TimeEnd:           pulumi.StringRef(javaDownloadRecordTimeEnd),
//				TimeStart:         pulumi.StringRef(javaDownloadRecordTimeStart),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetJavaDownloadsJavaDownloadRecords(ctx *pulumi.Context, args *GetJavaDownloadsJavaDownloadRecordsArgs, opts ...pulumi.InvokeOption) (*GetJavaDownloadsJavaDownloadRecordsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetJavaDownloadsJavaDownloadRecordsResult
	err := ctx.Invoke("oci:Jms/getJavaDownloadsJavaDownloadRecords:getJavaDownloadsJavaDownloadRecords", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getJavaDownloadsJavaDownloadRecords.
type GetJavaDownloadsJavaDownloadRecordsArgs struct {
	// Target Operating System architecture of the artifact.
	Architecture *string `pulumi:"architecture"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
	CompartmentId string `pulumi:"compartmentId"`
	// Unique Java family version identifier.
	FamilyVersion *string                                     `pulumi:"familyVersion"`
	Filters       []GetJavaDownloadsJavaDownloadRecordsFilter `pulumi:"filters"`
	// Target Operating System family of the artifact.
	OsFamily *string `pulumi:"osFamily"`
	// Packaging type detail of the artifact.
	PackageTypeDetail *string `pulumi:"packageTypeDetail"`
	// Unique Java release version identifier.
	ReleaseVersion *string `pulumi:"releaseVersion"`
	// The end of the time period for which reports are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeEnd *string `pulumi:"timeEnd"`
	// The start of the time period for which reports are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeStart *string `pulumi:"timeStart"`
}

// A collection of values returned by getJavaDownloadsJavaDownloadRecords.
type GetJavaDownloadsJavaDownloadRecordsResult struct {
	// The target Operating System architecture for the artifact.
	Architecture  *string `pulumi:"architecture"`
	CompartmentId string  `pulumi:"compartmentId"`
	// The Java family version identifier.
	FamilyVersion *string                                     `pulumi:"familyVersion"`
	Filters       []GetJavaDownloadsJavaDownloadRecordsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of java_download_record_collection.
	JavaDownloadRecordCollections []GetJavaDownloadsJavaDownloadRecordsJavaDownloadRecordCollection `pulumi:"javaDownloadRecordCollections"`
	// The target Operating System family for the artifact.
	OsFamily *string `pulumi:"osFamily"`
	// Additional information about the package type.
	PackageTypeDetail *string `pulumi:"packageTypeDetail"`
	// The Java release version identifier.
	ReleaseVersion *string `pulumi:"releaseVersion"`
	TimeEnd        *string `pulumi:"timeEnd"`
	TimeStart      *string `pulumi:"timeStart"`
}

func GetJavaDownloadsJavaDownloadRecordsOutput(ctx *pulumi.Context, args GetJavaDownloadsJavaDownloadRecordsOutputArgs, opts ...pulumi.InvokeOption) GetJavaDownloadsJavaDownloadRecordsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetJavaDownloadsJavaDownloadRecordsResultOutput, error) {
			args := v.(GetJavaDownloadsJavaDownloadRecordsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Jms/getJavaDownloadsJavaDownloadRecords:getJavaDownloadsJavaDownloadRecords", args, GetJavaDownloadsJavaDownloadRecordsResultOutput{}, options).(GetJavaDownloadsJavaDownloadRecordsResultOutput), nil
		}).(GetJavaDownloadsJavaDownloadRecordsResultOutput)
}

// A collection of arguments for invoking getJavaDownloadsJavaDownloadRecords.
type GetJavaDownloadsJavaDownloadRecordsOutputArgs struct {
	// Target Operating System architecture of the artifact.
	Architecture pulumi.StringPtrInput `pulumi:"architecture"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Unique Java family version identifier.
	FamilyVersion pulumi.StringPtrInput                               `pulumi:"familyVersion"`
	Filters       GetJavaDownloadsJavaDownloadRecordsFilterArrayInput `pulumi:"filters"`
	// Target Operating System family of the artifact.
	OsFamily pulumi.StringPtrInput `pulumi:"osFamily"`
	// Packaging type detail of the artifact.
	PackageTypeDetail pulumi.StringPtrInput `pulumi:"packageTypeDetail"`
	// Unique Java release version identifier.
	ReleaseVersion pulumi.StringPtrInput `pulumi:"releaseVersion"`
	// The end of the time period for which reports are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeEnd pulumi.StringPtrInput `pulumi:"timeEnd"`
	// The start of the time period for which reports are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeStart pulumi.StringPtrInput `pulumi:"timeStart"`
}

func (GetJavaDownloadsJavaDownloadRecordsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetJavaDownloadsJavaDownloadRecordsArgs)(nil)).Elem()
}

// A collection of values returned by getJavaDownloadsJavaDownloadRecords.
type GetJavaDownloadsJavaDownloadRecordsResultOutput struct{ *pulumi.OutputState }

func (GetJavaDownloadsJavaDownloadRecordsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetJavaDownloadsJavaDownloadRecordsResult)(nil)).Elem()
}

func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) ToGetJavaDownloadsJavaDownloadRecordsResultOutput() GetJavaDownloadsJavaDownloadRecordsResultOutput {
	return o
}

func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) ToGetJavaDownloadsJavaDownloadRecordsResultOutputWithContext(ctx context.Context) GetJavaDownloadsJavaDownloadRecordsResultOutput {
	return o
}

// The target Operating System architecture for the artifact.
func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) Architecture() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) *string { return v.Architecture }).(pulumi.StringPtrOutput)
}

func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The Java family version identifier.
func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) FamilyVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) *string { return v.FamilyVersion }).(pulumi.StringPtrOutput)
}

func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) Filters() GetJavaDownloadsJavaDownloadRecordsFilterArrayOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) []GetJavaDownloadsJavaDownloadRecordsFilter {
		return v.Filters
	}).(GetJavaDownloadsJavaDownloadRecordsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of java_download_record_collection.
func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) JavaDownloadRecordCollections() GetJavaDownloadsJavaDownloadRecordsJavaDownloadRecordCollectionArrayOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) []GetJavaDownloadsJavaDownloadRecordsJavaDownloadRecordCollection {
		return v.JavaDownloadRecordCollections
	}).(GetJavaDownloadsJavaDownloadRecordsJavaDownloadRecordCollectionArrayOutput)
}

// The target Operating System family for the artifact.
func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) OsFamily() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) *string { return v.OsFamily }).(pulumi.StringPtrOutput)
}

// Additional information about the package type.
func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) PackageTypeDetail() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) *string { return v.PackageTypeDetail }).(pulumi.StringPtrOutput)
}

// The Java release version identifier.
func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) ReleaseVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) *string { return v.ReleaseVersion }).(pulumi.StringPtrOutput)
}

func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) TimeEnd() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) *string { return v.TimeEnd }).(pulumi.StringPtrOutput)
}

func (o GetJavaDownloadsJavaDownloadRecordsResultOutput) TimeStart() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadRecordsResult) *string { return v.TimeStart }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetJavaDownloadsJavaDownloadRecordsResultOutput{})
}
