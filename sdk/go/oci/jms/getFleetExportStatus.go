// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package jms

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Fleet Export Status resource in Oracle Cloud Infrastructure Jms service.
//
// Returns last export status for the specified fleet.
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
//			_, err := jms.GetFleetExportStatus(ctx, &jms.GetFleetExportStatusArgs{
//				FleetId: testFleet.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetFleetExportStatus(ctx *pulumi.Context, args *GetFleetExportStatusArgs, opts ...pulumi.InvokeOption) (*GetFleetExportStatusResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetFleetExportStatusResult
	err := ctx.Invoke("oci:Jms/getFleetExportStatus:getFleetExportStatus", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFleetExportStatus.
type GetFleetExportStatusArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
	FleetId string `pulumi:"fleetId"`
}

// A collection of values returned by getFleetExportStatus.
type GetFleetExportStatusResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet.
	FleetId string `pulumi:"fleetId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The status of the latest export run.
	LatestRunStatus string `pulumi:"latestRunStatus"`
	// The date and time of the last export run.
	TimeLastRun string `pulumi:"timeLastRun"`
	// The date and time of the next export run.
	TimeNextRun string `pulumi:"timeNextRun"`
}

func GetFleetExportStatusOutput(ctx *pulumi.Context, args GetFleetExportStatusOutputArgs, opts ...pulumi.InvokeOption) GetFleetExportStatusResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetFleetExportStatusResultOutput, error) {
			args := v.(GetFleetExportStatusArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Jms/getFleetExportStatus:getFleetExportStatus", args, GetFleetExportStatusResultOutput{}, options).(GetFleetExportStatusResultOutput), nil
		}).(GetFleetExportStatusResultOutput)
}

// A collection of arguments for invoking getFleetExportStatus.
type GetFleetExportStatusOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
	FleetId pulumi.StringInput `pulumi:"fleetId"`
}

func (GetFleetExportStatusOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFleetExportStatusArgs)(nil)).Elem()
}

// A collection of values returned by getFleetExportStatus.
type GetFleetExportStatusResultOutput struct{ *pulumi.OutputState }

func (GetFleetExportStatusResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFleetExportStatusResult)(nil)).Elem()
}

func (o GetFleetExportStatusResultOutput) ToGetFleetExportStatusResultOutput() GetFleetExportStatusResultOutput {
	return o
}

func (o GetFleetExportStatusResultOutput) ToGetFleetExportStatusResultOutputWithContext(ctx context.Context) GetFleetExportStatusResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet.
func (o GetFleetExportStatusResultOutput) FleetId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFleetExportStatusResult) string { return v.FleetId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetFleetExportStatusResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetFleetExportStatusResult) string { return v.Id }).(pulumi.StringOutput)
}

// The status of the latest export run.
func (o GetFleetExportStatusResultOutput) LatestRunStatus() pulumi.StringOutput {
	return o.ApplyT(func(v GetFleetExportStatusResult) string { return v.LatestRunStatus }).(pulumi.StringOutput)
}

// The date and time of the last export run.
func (o GetFleetExportStatusResultOutput) TimeLastRun() pulumi.StringOutput {
	return o.ApplyT(func(v GetFleetExportStatusResult) string { return v.TimeLastRun }).(pulumi.StringOutput)
}

// The date and time of the next export run.
func (o GetFleetExportStatusResultOutput) TimeNextRun() pulumi.StringOutput {
	return o.ApplyT(func(v GetFleetExportStatusResult) string { return v.TimeNextRun }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFleetExportStatusResultOutput{})
}
