// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dataintegration

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Workspace Application Schedule resource in Oracle Cloud Infrastructure Data Integration service.
//
// # Retrieves schedule by schedule key
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/dataintegration"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := dataintegration.GetWorkspaceApplicationSchedule(ctx, &dataintegration.GetWorkspaceApplicationScheduleArgs{
//				ApplicationKey: workspaceApplicationScheduleApplicationKey,
//				ScheduleKey:    workspaceApplicationScheduleScheduleKey,
//				WorkspaceId:    testWorkspace.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupWorkspaceApplicationSchedule(ctx *pulumi.Context, args *LookupWorkspaceApplicationScheduleArgs, opts ...pulumi.InvokeOption) (*LookupWorkspaceApplicationScheduleResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupWorkspaceApplicationScheduleResult
	err := ctx.Invoke("oci:DataIntegration/getWorkspaceApplicationSchedule:getWorkspaceApplicationSchedule", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getWorkspaceApplicationSchedule.
type LookupWorkspaceApplicationScheduleArgs struct {
	// The application key.
	ApplicationKey string `pulumi:"applicationKey"`
	// Schedule Key
	ScheduleKey string `pulumi:"scheduleKey"`
	// The workspace ID.
	WorkspaceId string `pulumi:"workspaceId"`
}

// A collection of values returned by getWorkspaceApplicationSchedule.
type LookupWorkspaceApplicationScheduleResult struct {
	ApplicationKey string `pulumi:"applicationKey"`
	// The description of the aggregator.
	Description string `pulumi:"description"`
	// The model that holds the frequency details.
	FrequencyDetails []GetWorkspaceApplicationScheduleFrequencyDetail `pulumi:"frequencyDetails"`
	Id               string                                           `pulumi:"id"`
	// The identifier of the aggregator.
	Identifier string `pulumi:"identifier"`
	// A flag to indicate daylight saving.
	IsDaylightAdjustmentEnabled bool `pulumi:"isDaylightAdjustmentEnabled"`
	// The key of the aggregator object.
	Key string `pulumi:"key"`
	// A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadatas []GetWorkspaceApplicationScheduleMetadata `pulumi:"metadatas"`
	// The type of the object.
	ModelType string `pulumi:"modelType"`
	// This is a version number that is used by the service to upgrade objects if needed through releases of the service.
	ModelVersion string `pulumi:"modelVersion"`
	// Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name string `pulumi:"name"`
	// The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus int `pulumi:"objectStatus"`
	// This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
	ObjectVersion int `pulumi:"objectVersion"`
	// A reference to the object's parent.
	ParentReves       []GetWorkspaceApplicationScheduleParentRef        `pulumi:"parentReves"`
	RegistryMetadatas []GetWorkspaceApplicationScheduleRegistryMetadata `pulumi:"registryMetadatas"`
	ScheduleKey       string                                            `pulumi:"scheduleKey"`
	// The timezone for the schedule.
	Timezone    string `pulumi:"timezone"`
	WorkspaceId string `pulumi:"workspaceId"`
}

func LookupWorkspaceApplicationScheduleOutput(ctx *pulumi.Context, args LookupWorkspaceApplicationScheduleOutputArgs, opts ...pulumi.InvokeOption) LookupWorkspaceApplicationScheduleResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupWorkspaceApplicationScheduleResultOutput, error) {
			args := v.(LookupWorkspaceApplicationScheduleArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataIntegration/getWorkspaceApplicationSchedule:getWorkspaceApplicationSchedule", args, LookupWorkspaceApplicationScheduleResultOutput{}, options).(LookupWorkspaceApplicationScheduleResultOutput), nil
		}).(LookupWorkspaceApplicationScheduleResultOutput)
}

// A collection of arguments for invoking getWorkspaceApplicationSchedule.
type LookupWorkspaceApplicationScheduleOutputArgs struct {
	// The application key.
	ApplicationKey pulumi.StringInput `pulumi:"applicationKey"`
	// Schedule Key
	ScheduleKey pulumi.StringInput `pulumi:"scheduleKey"`
	// The workspace ID.
	WorkspaceId pulumi.StringInput `pulumi:"workspaceId"`
}

func (LookupWorkspaceApplicationScheduleOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupWorkspaceApplicationScheduleArgs)(nil)).Elem()
}

// A collection of values returned by getWorkspaceApplicationSchedule.
type LookupWorkspaceApplicationScheduleResultOutput struct{ *pulumi.OutputState }

func (LookupWorkspaceApplicationScheduleResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupWorkspaceApplicationScheduleResult)(nil)).Elem()
}

func (o LookupWorkspaceApplicationScheduleResultOutput) ToLookupWorkspaceApplicationScheduleResultOutput() LookupWorkspaceApplicationScheduleResultOutput {
	return o
}

func (o LookupWorkspaceApplicationScheduleResultOutput) ToLookupWorkspaceApplicationScheduleResultOutputWithContext(ctx context.Context) LookupWorkspaceApplicationScheduleResultOutput {
	return o
}

func (o LookupWorkspaceApplicationScheduleResultOutput) ApplicationKey() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.ApplicationKey }).(pulumi.StringOutput)
}

// The description of the aggregator.
func (o LookupWorkspaceApplicationScheduleResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.Description }).(pulumi.StringOutput)
}

// The model that holds the frequency details.
func (o LookupWorkspaceApplicationScheduleResultOutput) FrequencyDetails() GetWorkspaceApplicationScheduleFrequencyDetailArrayOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) []GetWorkspaceApplicationScheduleFrequencyDetail {
		return v.FrequencyDetails
	}).(GetWorkspaceApplicationScheduleFrequencyDetailArrayOutput)
}

func (o LookupWorkspaceApplicationScheduleResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.Id }).(pulumi.StringOutput)
}

// The identifier of the aggregator.
func (o LookupWorkspaceApplicationScheduleResultOutput) Identifier() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.Identifier }).(pulumi.StringOutput)
}

// A flag to indicate daylight saving.
func (o LookupWorkspaceApplicationScheduleResultOutput) IsDaylightAdjustmentEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) bool { return v.IsDaylightAdjustmentEnabled }).(pulumi.BoolOutput)
}

// The key of the aggregator object.
func (o LookupWorkspaceApplicationScheduleResultOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.Key }).(pulumi.StringOutput)
}

// A summary type containing information about the object including its key, name and when/who created/updated it.
func (o LookupWorkspaceApplicationScheduleResultOutput) Metadatas() GetWorkspaceApplicationScheduleMetadataArrayOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) []GetWorkspaceApplicationScheduleMetadata {
		return v.Metadatas
	}).(GetWorkspaceApplicationScheduleMetadataArrayOutput)
}

// The type of the object.
func (o LookupWorkspaceApplicationScheduleResultOutput) ModelType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.ModelType }).(pulumi.StringOutput)
}

// This is a version number that is used by the service to upgrade objects if needed through releases of the service.
func (o LookupWorkspaceApplicationScheduleResultOutput) ModelVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.ModelVersion }).(pulumi.StringOutput)
}

// Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
func (o LookupWorkspaceApplicationScheduleResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.Name }).(pulumi.StringOutput)
}

// The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
func (o LookupWorkspaceApplicationScheduleResultOutput) ObjectStatus() pulumi.IntOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) int { return v.ObjectStatus }).(pulumi.IntOutput)
}

// This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
func (o LookupWorkspaceApplicationScheduleResultOutput) ObjectVersion() pulumi.IntOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) int { return v.ObjectVersion }).(pulumi.IntOutput)
}

// A reference to the object's parent.
func (o LookupWorkspaceApplicationScheduleResultOutput) ParentReves() GetWorkspaceApplicationScheduleParentRefArrayOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) []GetWorkspaceApplicationScheduleParentRef {
		return v.ParentReves
	}).(GetWorkspaceApplicationScheduleParentRefArrayOutput)
}

func (o LookupWorkspaceApplicationScheduleResultOutput) RegistryMetadatas() GetWorkspaceApplicationScheduleRegistryMetadataArrayOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) []GetWorkspaceApplicationScheduleRegistryMetadata {
		return v.RegistryMetadatas
	}).(GetWorkspaceApplicationScheduleRegistryMetadataArrayOutput)
}

func (o LookupWorkspaceApplicationScheduleResultOutput) ScheduleKey() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.ScheduleKey }).(pulumi.StringOutput)
}

// The timezone for the schedule.
func (o LookupWorkspaceApplicationScheduleResultOutput) Timezone() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.Timezone }).(pulumi.StringOutput)
}

func (o LookupWorkspaceApplicationScheduleResultOutput) WorkspaceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceApplicationScheduleResult) string { return v.WorkspaceId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupWorkspaceApplicationScheduleResultOutput{})
}
