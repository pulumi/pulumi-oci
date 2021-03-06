// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package dataflow

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Invoke Runs in Oracle Cloud Infrastructure Data Flow service.
//
// Lists all runs of an application in the specified compartment.  Only one parameter other than compartmentId may also be included in a query. The query must include compartmentId. If the query does not include compartmentId, or includes compartmentId but two or more other parameters an error is returned.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataFlow"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := DataFlow.GetInvokeRuns(ctx, &dataflow.GetInvokeRunsArgs{
// 			CompartmentId:          _var.Compartment_id,
// 			ApplicationId:          pulumi.StringRef(oci_dataflow_application.Test_application.Id),
// 			DisplayName:            pulumi.StringRef(_var.Invoke_run_display_name),
// 			DisplayNameStartsWith:  pulumi.StringRef(_var.Invoke_run_display_name_starts_with),
// 			OwnerPrincipalId:       pulumi.StringRef(oci_dataflow_owner_principal.Test_owner_principal.Id),
// 			State:                  pulumi.StringRef(_var.Invoke_run_state),
// 			TimeCreatedGreaterThan: pulumi.StringRef(_var.Invoke_run_time_created_greater_than),
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetInvokeRuns(ctx *pulumi.Context, args *GetInvokeRunsArgs, opts ...pulumi.InvokeOption) (*GetInvokeRunsResult, error) {
	var rv GetInvokeRunsResult
	err := ctx.Invoke("oci:DataFlow/getInvokeRuns:getInvokeRuns", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getInvokeRuns.
type GetInvokeRunsArgs struct {
	// The ID of the application.
	ApplicationId *string `pulumi:"applicationId"`
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The query parameter for the Spark application name.
	DisplayName *string `pulumi:"displayName"`
	// The displayName prefix.
	DisplayNameStartsWith *string               `pulumi:"displayNameStartsWith"`
	Filters               []GetInvokeRunsFilter `pulumi:"filters"`
	// The OCID of the user who created the resource.
	OwnerPrincipalId *string `pulumi:"ownerPrincipalId"`
	// The LifecycleState of the run.
	State *string `pulumi:"state"`
	// The epoch time that the resource was created.
	TimeCreatedGreaterThan *string `pulumi:"timeCreatedGreaterThan"`
}

// A collection of values returned by getInvokeRuns.
type GetInvokeRunsResult struct {
	// The application ID.
	ApplicationId *string `pulumi:"applicationId"`
	// The OCID of a compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. This name is not necessarily unique.
	DisplayName           *string               `pulumi:"displayName"`
	DisplayNameStartsWith *string               `pulumi:"displayNameStartsWith"`
	Filters               []GetInvokeRunsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the user who created the resource.
	OwnerPrincipalId *string `pulumi:"ownerPrincipalId"`
	// The list of runs.
	Runs []GetInvokeRunsRun `pulumi:"runs"`
	// The current state of this run.
	State                  *string `pulumi:"state"`
	TimeCreatedGreaterThan *string `pulumi:"timeCreatedGreaterThan"`
}

func GetInvokeRunsOutput(ctx *pulumi.Context, args GetInvokeRunsOutputArgs, opts ...pulumi.InvokeOption) GetInvokeRunsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetInvokeRunsResult, error) {
			args := v.(GetInvokeRunsArgs)
			r, err := GetInvokeRuns(ctx, &args, opts...)
			var s GetInvokeRunsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetInvokeRunsResultOutput)
}

// A collection of arguments for invoking getInvokeRuns.
type GetInvokeRunsOutputArgs struct {
	// The ID of the application.
	ApplicationId pulumi.StringPtrInput `pulumi:"applicationId"`
	// The OCID of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The query parameter for the Spark application name.
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// The displayName prefix.
	DisplayNameStartsWith pulumi.StringPtrInput         `pulumi:"displayNameStartsWith"`
	Filters               GetInvokeRunsFilterArrayInput `pulumi:"filters"`
	// The OCID of the user who created the resource.
	OwnerPrincipalId pulumi.StringPtrInput `pulumi:"ownerPrincipalId"`
	// The LifecycleState of the run.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The epoch time that the resource was created.
	TimeCreatedGreaterThan pulumi.StringPtrInput `pulumi:"timeCreatedGreaterThan"`
}

func (GetInvokeRunsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetInvokeRunsArgs)(nil)).Elem()
}

// A collection of values returned by getInvokeRuns.
type GetInvokeRunsResultOutput struct{ *pulumi.OutputState }

func (GetInvokeRunsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetInvokeRunsResult)(nil)).Elem()
}

func (o GetInvokeRunsResultOutput) ToGetInvokeRunsResultOutput() GetInvokeRunsResultOutput {
	return o
}

func (o GetInvokeRunsResultOutput) ToGetInvokeRunsResultOutputWithContext(ctx context.Context) GetInvokeRunsResultOutput {
	return o
}

// The application ID.
func (o GetInvokeRunsResultOutput) ApplicationId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetInvokeRunsResult) *string { return v.ApplicationId }).(pulumi.StringPtrOutput)
}

// The OCID of a compartment.
func (o GetInvokeRunsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetInvokeRunsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. This name is not necessarily unique.
func (o GetInvokeRunsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetInvokeRunsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetInvokeRunsResultOutput) DisplayNameStartsWith() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetInvokeRunsResult) *string { return v.DisplayNameStartsWith }).(pulumi.StringPtrOutput)
}

func (o GetInvokeRunsResultOutput) Filters() GetInvokeRunsFilterArrayOutput {
	return o.ApplyT(func(v GetInvokeRunsResult) []GetInvokeRunsFilter { return v.Filters }).(GetInvokeRunsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetInvokeRunsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetInvokeRunsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the user who created the resource.
func (o GetInvokeRunsResultOutput) OwnerPrincipalId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetInvokeRunsResult) *string { return v.OwnerPrincipalId }).(pulumi.StringPtrOutput)
}

// The list of runs.
func (o GetInvokeRunsResultOutput) Runs() GetInvokeRunsRunArrayOutput {
	return o.ApplyT(func(v GetInvokeRunsResult) []GetInvokeRunsRun { return v.Runs }).(GetInvokeRunsRunArrayOutput)
}

// The current state of this run.
func (o GetInvokeRunsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetInvokeRunsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func (o GetInvokeRunsResultOutput) TimeCreatedGreaterThan() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetInvokeRunsResult) *string { return v.TimeCreatedGreaterThan }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetInvokeRunsResultOutput{})
}
