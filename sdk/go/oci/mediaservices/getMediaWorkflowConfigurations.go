// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mediaservices

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Media Workflow Configurations in Oracle Cloud Infrastructure Media Services service.
//
// Returns a list of MediaWorkflowConfigurations.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/MediaServices"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := MediaServices.GetMediaWorkflowConfigurations(ctx, &mediaservices.GetMediaWorkflowConfigurationsArgs{
//				CompartmentId: pulumi.StringRef(_var.Compartment_id),
//				DisplayName:   pulumi.StringRef(_var.Media_workflow_configuration_display_name),
//				Id:            pulumi.StringRef(_var.Media_workflow_configuration_id),
//				State:         pulumi.StringRef(_var.Media_workflow_configuration_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMediaWorkflowConfigurations(ctx *pulumi.Context, args *GetMediaWorkflowConfigurationsArgs, opts ...pulumi.InvokeOption) (*GetMediaWorkflowConfigurationsResult, error) {
	var rv GetMediaWorkflowConfigurationsResult
	err := ctx.Invoke("oci:MediaServices/getMediaWorkflowConfigurations:getMediaWorkflowConfigurations", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMediaWorkflowConfigurations.
type GetMediaWorkflowConfigurationsArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only the resources that match the entire display name given.
	DisplayName *string                                `pulumi:"displayName"`
	Filters     []GetMediaWorkflowConfigurationsFilter `pulumi:"filters"`
	// Unique MediaWorkflowConfiguration identifier.
	Id *string `pulumi:"id"`
	// A filter to return only the resources with lifecycleState matching the given lifecycleState.
	State *string `pulumi:"state"`
}

// A collection of values returned by getMediaWorkflowConfigurations.
type GetMediaWorkflowConfigurationsResult struct {
	// Compartment Identifier.
	CompartmentId *string `pulumi:"compartmentId"`
	// Display name for the MediaWorkflowConfiguration. Avoid entering confidential information.
	DisplayName *string                                `pulumi:"displayName"`
	Filters     []GetMediaWorkflowConfigurationsFilter `pulumi:"filters"`
	// Unique identifier that is immutable on creation.
	Id *string `pulumi:"id"`
	// The list of media_workflow_configuration_collection.
	MediaWorkflowConfigurationCollections []GetMediaWorkflowConfigurationsMediaWorkflowConfigurationCollection `pulumi:"mediaWorkflowConfigurationCollections"`
	// The current state of the MediaWorkflowConfiguration.
	State *string `pulumi:"state"`
}

func GetMediaWorkflowConfigurationsOutput(ctx *pulumi.Context, args GetMediaWorkflowConfigurationsOutputArgs, opts ...pulumi.InvokeOption) GetMediaWorkflowConfigurationsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetMediaWorkflowConfigurationsResult, error) {
			args := v.(GetMediaWorkflowConfigurationsArgs)
			r, err := GetMediaWorkflowConfigurations(ctx, &args, opts...)
			var s GetMediaWorkflowConfigurationsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetMediaWorkflowConfigurationsResultOutput)
}

// A collection of arguments for invoking getMediaWorkflowConfigurations.
type GetMediaWorkflowConfigurationsOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only the resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                          `pulumi:"displayName"`
	Filters     GetMediaWorkflowConfigurationsFilterArrayInput `pulumi:"filters"`
	// Unique MediaWorkflowConfiguration identifier.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only the resources with lifecycleState matching the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetMediaWorkflowConfigurationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMediaWorkflowConfigurationsArgs)(nil)).Elem()
}

// A collection of values returned by getMediaWorkflowConfigurations.
type GetMediaWorkflowConfigurationsResultOutput struct{ *pulumi.OutputState }

func (GetMediaWorkflowConfigurationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMediaWorkflowConfigurationsResult)(nil)).Elem()
}

func (o GetMediaWorkflowConfigurationsResultOutput) ToGetMediaWorkflowConfigurationsResultOutput() GetMediaWorkflowConfigurationsResultOutput {
	return o
}

func (o GetMediaWorkflowConfigurationsResultOutput) ToGetMediaWorkflowConfigurationsResultOutputWithContext(ctx context.Context) GetMediaWorkflowConfigurationsResultOutput {
	return o
}

// Compartment Identifier.
func (o GetMediaWorkflowConfigurationsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMediaWorkflowConfigurationsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// Display name for the MediaWorkflowConfiguration. Avoid entering confidential information.
func (o GetMediaWorkflowConfigurationsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMediaWorkflowConfigurationsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetMediaWorkflowConfigurationsResultOutput) Filters() GetMediaWorkflowConfigurationsFilterArrayOutput {
	return o.ApplyT(func(v GetMediaWorkflowConfigurationsResult) []GetMediaWorkflowConfigurationsFilter { return v.Filters }).(GetMediaWorkflowConfigurationsFilterArrayOutput)
}

// Unique identifier that is immutable on creation.
func (o GetMediaWorkflowConfigurationsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMediaWorkflowConfigurationsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The list of media_workflow_configuration_collection.
func (o GetMediaWorkflowConfigurationsResultOutput) MediaWorkflowConfigurationCollections() GetMediaWorkflowConfigurationsMediaWorkflowConfigurationCollectionArrayOutput {
	return o.ApplyT(func(v GetMediaWorkflowConfigurationsResult) []GetMediaWorkflowConfigurationsMediaWorkflowConfigurationCollection {
		return v.MediaWorkflowConfigurationCollections
	}).(GetMediaWorkflowConfigurationsMediaWorkflowConfigurationCollectionArrayOutput)
}

// The current state of the MediaWorkflowConfiguration.
func (o GetMediaWorkflowConfigurationsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMediaWorkflowConfigurationsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMediaWorkflowConfigurationsResultOutput{})
}