// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package jms

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Java Download Reports in Oracle Cloud Infrastructure Jms Java Downloads service.
//
// Returns a list of JavaDownloadReports.
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
//			_, err := jms.GetJavaDownloadsJavaDownloadReports(ctx, &jms.GetJavaDownloadsJavaDownloadReportsArgs{
//				CompartmentId:        tenancyOcid,
//				DisplayName:          pulumi.StringRef(javaDownloadReportDisplayName),
//				JavaDownloadReportId: pulumi.StringRef(testJavaDownloadReport.Id),
//				State:                pulumi.StringRef(javaDownloadReportState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetJavaDownloadsJavaDownloadReports(ctx *pulumi.Context, args *GetJavaDownloadsJavaDownloadReportsArgs, opts ...pulumi.InvokeOption) (*GetJavaDownloadsJavaDownloadReportsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetJavaDownloadsJavaDownloadReportsResult
	err := ctx.Invoke("oci:Jms/getJavaDownloadsJavaDownloadReports:getJavaDownloadsJavaDownloadReports", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getJavaDownloadsJavaDownloadReports.
type GetJavaDownloadsJavaDownloadReportsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the display name.
	DisplayName *string                                     `pulumi:"displayName"`
	Filters     []GetJavaDownloadsJavaDownloadReportsFilter `pulumi:"filters"`
	// Unique Java download report identifier.
	JavaDownloadReportId *string `pulumi:"javaDownloadReportId"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State *string `pulumi:"state"`
}

// A collection of values returned by getJavaDownloadsJavaDownloadReports.
type GetJavaDownloadsJavaDownloadReportsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy scoped to the Java download report.
	CompartmentId string `pulumi:"compartmentId"`
	// Display name for the Java download report.
	DisplayName *string                                     `pulumi:"displayName"`
	Filters     []GetJavaDownloadsJavaDownloadReportsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of java_download_report_collection.
	JavaDownloadReportCollections []GetJavaDownloadsJavaDownloadReportsJavaDownloadReportCollection `pulumi:"javaDownloadReportCollections"`
	JavaDownloadReportId          *string                                                           `pulumi:"javaDownloadReportId"`
	// The current state of the Java download report.
	State *string `pulumi:"state"`
}

func GetJavaDownloadsJavaDownloadReportsOutput(ctx *pulumi.Context, args GetJavaDownloadsJavaDownloadReportsOutputArgs, opts ...pulumi.InvokeOption) GetJavaDownloadsJavaDownloadReportsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetJavaDownloadsJavaDownloadReportsResultOutput, error) {
			args := v.(GetJavaDownloadsJavaDownloadReportsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Jms/getJavaDownloadsJavaDownloadReports:getJavaDownloadsJavaDownloadReports", args, GetJavaDownloadsJavaDownloadReportsResultOutput{}, options).(GetJavaDownloadsJavaDownloadReportsResultOutput), nil
		}).(GetJavaDownloadsJavaDownloadReportsResultOutput)
}

// A collection of arguments for invoking getJavaDownloadsJavaDownloadReports.
type GetJavaDownloadsJavaDownloadReportsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the display name.
	DisplayName pulumi.StringPtrInput                               `pulumi:"displayName"`
	Filters     GetJavaDownloadsJavaDownloadReportsFilterArrayInput `pulumi:"filters"`
	// Unique Java download report identifier.
	JavaDownloadReportId pulumi.StringPtrInput `pulumi:"javaDownloadReportId"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetJavaDownloadsJavaDownloadReportsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetJavaDownloadsJavaDownloadReportsArgs)(nil)).Elem()
}

// A collection of values returned by getJavaDownloadsJavaDownloadReports.
type GetJavaDownloadsJavaDownloadReportsResultOutput struct{ *pulumi.OutputState }

func (GetJavaDownloadsJavaDownloadReportsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetJavaDownloadsJavaDownloadReportsResult)(nil)).Elem()
}

func (o GetJavaDownloadsJavaDownloadReportsResultOutput) ToGetJavaDownloadsJavaDownloadReportsResultOutput() GetJavaDownloadsJavaDownloadReportsResultOutput {
	return o
}

func (o GetJavaDownloadsJavaDownloadReportsResultOutput) ToGetJavaDownloadsJavaDownloadReportsResultOutputWithContext(ctx context.Context) GetJavaDownloadsJavaDownloadReportsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy scoped to the Java download report.
func (o GetJavaDownloadsJavaDownloadReportsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadReportsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Display name for the Java download report.
func (o GetJavaDownloadsJavaDownloadReportsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadReportsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetJavaDownloadsJavaDownloadReportsResultOutput) Filters() GetJavaDownloadsJavaDownloadReportsFilterArrayOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadReportsResult) []GetJavaDownloadsJavaDownloadReportsFilter {
		return v.Filters
	}).(GetJavaDownloadsJavaDownloadReportsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetJavaDownloadsJavaDownloadReportsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadReportsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of java_download_report_collection.
func (o GetJavaDownloadsJavaDownloadReportsResultOutput) JavaDownloadReportCollections() GetJavaDownloadsJavaDownloadReportsJavaDownloadReportCollectionArrayOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadReportsResult) []GetJavaDownloadsJavaDownloadReportsJavaDownloadReportCollection {
		return v.JavaDownloadReportCollections
	}).(GetJavaDownloadsJavaDownloadReportsJavaDownloadReportCollectionArrayOutput)
}

func (o GetJavaDownloadsJavaDownloadReportsResultOutput) JavaDownloadReportId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadReportsResult) *string { return v.JavaDownloadReportId }).(pulumi.StringPtrOutput)
}

// The current state of the Java download report.
func (o GetJavaDownloadsJavaDownloadReportsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaDownloadReportsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetJavaDownloadsJavaDownloadReportsResultOutput{})
}
