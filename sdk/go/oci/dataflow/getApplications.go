// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dataflow

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Applications in Oracle Cloud Infrastructure Data Flow service.
//
// Lists all applications in the specified compartment. Only one parameter other than compartmentId may also be included in a query. The query must include compartmentId. If the query does not include compartmentId, or includes compartmentId but two or more other parameters an error is returned.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataFlow"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataFlow.GetApplications(ctx, &dataflow.GetApplicationsArgs{
//				CompartmentId:         _var.Compartment_id,
//				DisplayName:           pulumi.StringRef(_var.Application_display_name),
//				DisplayNameStartsWith: pulumi.StringRef(_var.Application_display_name_starts_with),
//				OwnerPrincipalId:      pulumi.StringRef(oci_dataflow_owner_principal.Test_owner_principal.Id),
//				SparkVersion:          pulumi.StringRef(_var.Application_spark_version),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetApplications(ctx *pulumi.Context, args *GetApplicationsArgs, opts ...pulumi.InvokeOption) (*GetApplicationsResult, error) {
	var rv GetApplicationsResult
	err := ctx.Invoke("oci:DataFlow/getApplications:getApplications", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getApplications.
type GetApplicationsArgs struct {
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The query parameter for the Spark application name.
	DisplayName *string `pulumi:"displayName"`
	// The displayName prefix.
	DisplayNameStartsWith *string                 `pulumi:"displayNameStartsWith"`
	Filters               []GetApplicationsFilter `pulumi:"filters"`
	// The OCID of the user who created the resource.
	OwnerPrincipalId *string `pulumi:"ownerPrincipalId"`
	// The Spark version utilized to run the application.
	SparkVersion *string `pulumi:"sparkVersion"`
}

// A collection of values returned by getApplications.
type GetApplicationsResult struct {
	// The list of applications.
	Applications []GetApplicationsApplication `pulumi:"applications"`
	// The OCID of a compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. This name is not necessarily unique.
	DisplayName           *string                 `pulumi:"displayName"`
	DisplayNameStartsWith *string                 `pulumi:"displayNameStartsWith"`
	Filters               []GetApplicationsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the user who created the resource.
	OwnerPrincipalId *string `pulumi:"ownerPrincipalId"`
	// The Spark version utilized to run the application.
	SparkVersion *string `pulumi:"sparkVersion"`
}

func GetApplicationsOutput(ctx *pulumi.Context, args GetApplicationsOutputArgs, opts ...pulumi.InvokeOption) GetApplicationsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetApplicationsResult, error) {
			args := v.(GetApplicationsArgs)
			r, err := GetApplications(ctx, &args, opts...)
			var s GetApplicationsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetApplicationsResultOutput)
}

// A collection of arguments for invoking getApplications.
type GetApplicationsOutputArgs struct {
	// The OCID of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The query parameter for the Spark application name.
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// The displayName prefix.
	DisplayNameStartsWith pulumi.StringPtrInput           `pulumi:"displayNameStartsWith"`
	Filters               GetApplicationsFilterArrayInput `pulumi:"filters"`
	// The OCID of the user who created the resource.
	OwnerPrincipalId pulumi.StringPtrInput `pulumi:"ownerPrincipalId"`
	// The Spark version utilized to run the application.
	SparkVersion pulumi.StringPtrInput `pulumi:"sparkVersion"`
}

func (GetApplicationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetApplicationsArgs)(nil)).Elem()
}

// A collection of values returned by getApplications.
type GetApplicationsResultOutput struct{ *pulumi.OutputState }

func (GetApplicationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetApplicationsResult)(nil)).Elem()
}

func (o GetApplicationsResultOutput) ToGetApplicationsResultOutput() GetApplicationsResultOutput {
	return o
}

func (o GetApplicationsResultOutput) ToGetApplicationsResultOutputWithContext(ctx context.Context) GetApplicationsResultOutput {
	return o
}

// The list of applications.
func (o GetApplicationsResultOutput) Applications() GetApplicationsApplicationArrayOutput {
	return o.ApplyT(func(v GetApplicationsResult) []GetApplicationsApplication { return v.Applications }).(GetApplicationsApplicationArrayOutput)
}

// The OCID of a compartment.
func (o GetApplicationsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetApplicationsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. This name is not necessarily unique.
func (o GetApplicationsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApplicationsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetApplicationsResultOutput) DisplayNameStartsWith() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApplicationsResult) *string { return v.DisplayNameStartsWith }).(pulumi.StringPtrOutput)
}

func (o GetApplicationsResultOutput) Filters() GetApplicationsFilterArrayOutput {
	return o.ApplyT(func(v GetApplicationsResult) []GetApplicationsFilter { return v.Filters }).(GetApplicationsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetApplicationsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetApplicationsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the user who created the resource.
func (o GetApplicationsResultOutput) OwnerPrincipalId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApplicationsResult) *string { return v.OwnerPrincipalId }).(pulumi.StringPtrOutput)
}

// The Spark version utilized to run the application.
func (o GetApplicationsResultOutput) SparkVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApplicationsResult) *string { return v.SparkVersion }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetApplicationsResultOutput{})
}