// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Reports in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of all the reports in the compartment. It contains information such as report generation time.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataSafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataSafe.GetReports(ctx, &datasafe.GetReportsArgs{
//				CompartmentId:          _var.Compartment_id,
//				AccessLevel:            pulumi.StringRef(_var.Report_access_level),
//				CompartmentIdInSubtree: pulumi.BoolRef(_var.Report_compartment_id_in_subtree),
//				DisplayName:            pulumi.StringRef(_var.Report_display_name),
//				ReportDefinitionId:     pulumi.StringRef(oci_data_safe_report_definition.Test_report_definition.Id),
//				State:                  pulumi.StringRef(_var.Report_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetReports(ctx *pulumi.Context, args *GetReportsArgs, opts ...pulumi.InvokeOption) (*GetReportsResult, error) {
	var rv GetReportsResult
	err := ctx.Invoke("oci:DataSafe/getReports:getReports", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getReports.
type GetReportsArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel *string `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree *bool `pulumi:"compartmentIdInSubtree"`
	// The name of the report definition to query.
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetReportsFilter `pulumi:"filters"`
	// The ID of the report definition to filter the list of reports
	ReportDefinitionId *string `pulumi:"reportDefinitionId"`
	// An optional filter to return only resources that match the specified lifecycle state.
	State *string `pulumi:"state"`
}

// A collection of values returned by getReports.
type GetReportsResult struct {
	AccessLevel *string `pulumi:"accessLevel"`
	// The OCID of the compartment containing the report.
	CompartmentId          string `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool  `pulumi:"compartmentIdInSubtree"`
	// Name of the report.
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetReportsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of report_collection.
	ReportCollections []GetReportsReportCollection `pulumi:"reportCollections"`
	// The OCID of the report definition.
	ReportDefinitionId *string `pulumi:"reportDefinitionId"`
	// The current state of the report.
	State *string `pulumi:"state"`
}

func GetReportsOutput(ctx *pulumi.Context, args GetReportsOutputArgs, opts ...pulumi.InvokeOption) GetReportsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetReportsResult, error) {
			args := v.(GetReportsArgs)
			r, err := GetReports(ctx, &args, opts...)
			var s GetReportsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetReportsResultOutput)
}

// A collection of arguments for invoking getReports.
type GetReportsOutputArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel pulumi.StringPtrInput `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"compartmentIdInSubtree"`
	// The name of the report definition to query.
	DisplayName pulumi.StringPtrInput      `pulumi:"displayName"`
	Filters     GetReportsFilterArrayInput `pulumi:"filters"`
	// The ID of the report definition to filter the list of reports
	ReportDefinitionId pulumi.StringPtrInput `pulumi:"reportDefinitionId"`
	// An optional filter to return only resources that match the specified lifecycle state.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetReportsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetReportsArgs)(nil)).Elem()
}

// A collection of values returned by getReports.
type GetReportsResultOutput struct{ *pulumi.OutputState }

func (GetReportsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetReportsResult)(nil)).Elem()
}

func (o GetReportsResultOutput) ToGetReportsResultOutput() GetReportsResultOutput {
	return o
}

func (o GetReportsResultOutput) ToGetReportsResultOutputWithContext(ctx context.Context) GetReportsResultOutput {
	return o
}

func (o GetReportsResultOutput) AccessLevel() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetReportsResult) *string { return v.AccessLevel }).(pulumi.StringPtrOutput)
}

// The OCID of the compartment containing the report.
func (o GetReportsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetReportsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetReportsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetReportsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// Name of the report.
func (o GetReportsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetReportsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetReportsResultOutput) Filters() GetReportsFilterArrayOutput {
	return o.ApplyT(func(v GetReportsResult) []GetReportsFilter { return v.Filters }).(GetReportsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetReportsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetReportsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of report_collection.
func (o GetReportsResultOutput) ReportCollections() GetReportsReportCollectionArrayOutput {
	return o.ApplyT(func(v GetReportsResult) []GetReportsReportCollection { return v.ReportCollections }).(GetReportsReportCollectionArrayOutput)
}

// The OCID of the report definition.
func (o GetReportsResultOutput) ReportDefinitionId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetReportsResult) *string { return v.ReportDefinitionId }).(pulumi.StringPtrOutput)
}

// The current state of the report.
func (o GetReportsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetReportsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetReportsResultOutput{})
}