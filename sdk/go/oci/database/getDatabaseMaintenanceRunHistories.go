// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Maintenance Run Histories in Oracle Cloud Infrastructure Database service.
//
// Gets a list of the maintenance run histories in the specified compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.GetDatabaseMaintenanceRunHistories(ctx, &database.GetDatabaseMaintenanceRunHistoriesArgs{
//				CompartmentId:      compartmentId,
//				AvailabilityDomain: pulumi.StringRef(maintenanceRunHistoryAvailabilityDomain),
//				MaintenanceType:    pulumi.StringRef(maintenanceRunHistoryMaintenanceType),
//				State:              pulumi.StringRef(maintenanceRunHistoryState),
//				TargetResourceId:   pulumi.StringRef(testTargetResource.Id),
//				TargetResourceType: pulumi.StringRef(maintenanceRunHistoryTargetResourceType),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDatabaseMaintenanceRunHistories(ctx *pulumi.Context, args *GetDatabaseMaintenanceRunHistoriesArgs, opts ...pulumi.InvokeOption) (*GetDatabaseMaintenanceRunHistoriesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDatabaseMaintenanceRunHistoriesResult
	err := ctx.Invoke("oci:Database/getDatabaseMaintenanceRunHistories:getDatabaseMaintenanceRunHistories", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDatabaseMaintenanceRunHistories.
type GetDatabaseMaintenanceRunHistoriesArgs struct {
	// A filter to return only resources that match the given availability domain exactly.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string                                     `pulumi:"compartmentId"`
	Filters       []GetDatabaseMaintenanceRunHistoriesFilter `pulumi:"filters"`
	// The maintenance type.
	MaintenanceType *string `pulumi:"maintenanceType"`
	// The state of the maintenance run history.
	State *string `pulumi:"state"`
	// The target resource ID.
	TargetResourceId *string `pulumi:"targetResourceId"`
	// The type of the target resource.
	TargetResourceType *string `pulumi:"targetResourceType"`
}

// A collection of values returned by getDatabaseMaintenanceRunHistories.
type GetDatabaseMaintenanceRunHistoriesResult struct {
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The OCID of the compartment.
	CompartmentId string                                     `pulumi:"compartmentId"`
	Filters       []GetDatabaseMaintenanceRunHistoriesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of maintenance_run_histories.
	MaintenanceRunHistories []GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory `pulumi:"maintenanceRunHistories"`
	// Maintenance type.
	MaintenanceType *string `pulumi:"maintenanceType"`
	// The current state of the maintenance run. For Autonomous Database Serverless instances, valid states are IN_PROGRESS, SUCCEEDED, and FAILED.
	State *string `pulumi:"state"`
	// The ID of the target resource on which the maintenance run occurs.
	TargetResourceId *string `pulumi:"targetResourceId"`
	// The type of the target resource on which the maintenance run occurs.
	TargetResourceType *string `pulumi:"targetResourceType"`
}

func GetDatabaseMaintenanceRunHistoriesOutput(ctx *pulumi.Context, args GetDatabaseMaintenanceRunHistoriesOutputArgs, opts ...pulumi.InvokeOption) GetDatabaseMaintenanceRunHistoriesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDatabaseMaintenanceRunHistoriesResultOutput, error) {
			args := v.(GetDatabaseMaintenanceRunHistoriesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getDatabaseMaintenanceRunHistories:getDatabaseMaintenanceRunHistories", args, GetDatabaseMaintenanceRunHistoriesResultOutput{}, options).(GetDatabaseMaintenanceRunHistoriesResultOutput), nil
		}).(GetDatabaseMaintenanceRunHistoriesResultOutput)
}

// A collection of arguments for invoking getDatabaseMaintenanceRunHistories.
type GetDatabaseMaintenanceRunHistoriesOutputArgs struct {
	// A filter to return only resources that match the given availability domain exactly.
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput                                 `pulumi:"compartmentId"`
	Filters       GetDatabaseMaintenanceRunHistoriesFilterArrayInput `pulumi:"filters"`
	// The maintenance type.
	MaintenanceType pulumi.StringPtrInput `pulumi:"maintenanceType"`
	// The state of the maintenance run history.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The target resource ID.
	TargetResourceId pulumi.StringPtrInput `pulumi:"targetResourceId"`
	// The type of the target resource.
	TargetResourceType pulumi.StringPtrInput `pulumi:"targetResourceType"`
}

func (GetDatabaseMaintenanceRunHistoriesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDatabaseMaintenanceRunHistoriesArgs)(nil)).Elem()
}

// A collection of values returned by getDatabaseMaintenanceRunHistories.
type GetDatabaseMaintenanceRunHistoriesResultOutput struct{ *pulumi.OutputState }

func (GetDatabaseMaintenanceRunHistoriesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDatabaseMaintenanceRunHistoriesResult)(nil)).Elem()
}

func (o GetDatabaseMaintenanceRunHistoriesResultOutput) ToGetDatabaseMaintenanceRunHistoriesResultOutput() GetDatabaseMaintenanceRunHistoriesResultOutput {
	return o
}

func (o GetDatabaseMaintenanceRunHistoriesResultOutput) ToGetDatabaseMaintenanceRunHistoriesResultOutputWithContext(ctx context.Context) GetDatabaseMaintenanceRunHistoriesResultOutput {
	return o
}

func (o GetDatabaseMaintenanceRunHistoriesResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDatabaseMaintenanceRunHistoriesResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

// The OCID of the compartment.
func (o GetDatabaseMaintenanceRunHistoriesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseMaintenanceRunHistoriesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetDatabaseMaintenanceRunHistoriesResultOutput) Filters() GetDatabaseMaintenanceRunHistoriesFilterArrayOutput {
	return o.ApplyT(func(v GetDatabaseMaintenanceRunHistoriesResult) []GetDatabaseMaintenanceRunHistoriesFilter {
		return v.Filters
	}).(GetDatabaseMaintenanceRunHistoriesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDatabaseMaintenanceRunHistoriesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseMaintenanceRunHistoriesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of maintenance_run_histories.
func (o GetDatabaseMaintenanceRunHistoriesResultOutput) MaintenanceRunHistories() GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryArrayOutput {
	return o.ApplyT(func(v GetDatabaseMaintenanceRunHistoriesResult) []GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory {
		return v.MaintenanceRunHistories
	}).(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryArrayOutput)
}

// Maintenance type.
func (o GetDatabaseMaintenanceRunHistoriesResultOutput) MaintenanceType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDatabaseMaintenanceRunHistoriesResult) *string { return v.MaintenanceType }).(pulumi.StringPtrOutput)
}

// The current state of the maintenance run. For Autonomous Database Serverless instances, valid states are IN_PROGRESS, SUCCEEDED, and FAILED.
func (o GetDatabaseMaintenanceRunHistoriesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDatabaseMaintenanceRunHistoriesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The ID of the target resource on which the maintenance run occurs.
func (o GetDatabaseMaintenanceRunHistoriesResultOutput) TargetResourceId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDatabaseMaintenanceRunHistoriesResult) *string { return v.TargetResourceId }).(pulumi.StringPtrOutput)
}

// The type of the target resource on which the maintenance run occurs.
func (o GetDatabaseMaintenanceRunHistoriesResultOutput) TargetResourceType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDatabaseMaintenanceRunHistoriesResult) *string { return v.TargetResourceType }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDatabaseMaintenanceRunHistoriesResultOutput{})
}
