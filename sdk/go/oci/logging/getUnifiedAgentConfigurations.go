// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package logging

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Unified Agent Configurations in Oracle Cloud Infrastructure Logging service.
//
// Lists all unified agent configurations in the specified compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Logging"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Logging.GetUnifiedAgentConfigurations(ctx, &logging.GetUnifiedAgentConfigurationsArgs{
//				CompartmentId:            _var.Compartment_id,
//				DisplayName:              pulumi.StringRef(_var.Unified_agent_configuration_display_name),
//				GroupId:                  pulumi.StringRef(oci_identity_group.Test_group.Id),
//				IsCompartmentIdInSubtree: pulumi.BoolRef(_var.Unified_agent_configuration_is_compartment_id_in_subtree),
//				LogId:                    pulumi.StringRef(oci_logging_log.Test_log.Id),
//				State:                    pulumi.StringRef(_var.Unified_agent_configuration_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetUnifiedAgentConfigurations(ctx *pulumi.Context, args *GetUnifiedAgentConfigurationsArgs, opts ...pulumi.InvokeOption) (*GetUnifiedAgentConfigurationsResult, error) {
	var rv GetUnifiedAgentConfigurationsResult
	err := ctx.Invoke("oci:Logging/getUnifiedAgentConfigurations:getUnifiedAgentConfigurations", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getUnifiedAgentConfigurations.
type GetUnifiedAgentConfigurationsArgs struct {
	// Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
	CompartmentId string `pulumi:"compartmentId"`
	// Resource name
	DisplayName *string                               `pulumi:"displayName"`
	Filters     []GetUnifiedAgentConfigurationsFilter `pulumi:"filters"`
	// The OCID of a group or a dynamic group.
	GroupId *string `pulumi:"groupId"`
	// Specifies whether or not nested compartments should be traversed. Defaults to false.
	IsCompartmentIdInSubtree *bool `pulumi:"isCompartmentIdInSubtree"`
	// Custom log OCID to list resources with the log as destination.
	LogId *string `pulumi:"logId"`
	// Lifecycle state of the log object
	State *string `pulumi:"state"`
}

// A collection of values returned by getUnifiedAgentConfigurations.
type GetUnifiedAgentConfigurationsResult struct {
	// The OCID of the compartment that the resource belongs to.
	CompartmentId string `pulumi:"compartmentId"`
	// The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
	DisplayName *string                               `pulumi:"displayName"`
	Filters     []GetUnifiedAgentConfigurationsFilter `pulumi:"filters"`
	GroupId     *string                               `pulumi:"groupId"`
	// The provider-assigned unique ID for this managed resource.
	Id                       string  `pulumi:"id"`
	IsCompartmentIdInSubtree *bool   `pulumi:"isCompartmentIdInSubtree"`
	LogId                    *string `pulumi:"logId"`
	// The pipeline state.
	State *string `pulumi:"state"`
	// The list of unified_agent_configuration_collection.
	UnifiedAgentConfigurationCollections []GetUnifiedAgentConfigurationsUnifiedAgentConfigurationCollection `pulumi:"unifiedAgentConfigurationCollections"`
}

func GetUnifiedAgentConfigurationsOutput(ctx *pulumi.Context, args GetUnifiedAgentConfigurationsOutputArgs, opts ...pulumi.InvokeOption) GetUnifiedAgentConfigurationsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetUnifiedAgentConfigurationsResult, error) {
			args := v.(GetUnifiedAgentConfigurationsArgs)
			r, err := GetUnifiedAgentConfigurations(ctx, &args, opts...)
			var s GetUnifiedAgentConfigurationsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetUnifiedAgentConfigurationsResultOutput)
}

// A collection of arguments for invoking getUnifiedAgentConfigurations.
type GetUnifiedAgentConfigurationsOutputArgs struct {
	// Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Resource name
	DisplayName pulumi.StringPtrInput                         `pulumi:"displayName"`
	Filters     GetUnifiedAgentConfigurationsFilterArrayInput `pulumi:"filters"`
	// The OCID of a group or a dynamic group.
	GroupId pulumi.StringPtrInput `pulumi:"groupId"`
	// Specifies whether or not nested compartments should be traversed. Defaults to false.
	IsCompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"isCompartmentIdInSubtree"`
	// Custom log OCID to list resources with the log as destination.
	LogId pulumi.StringPtrInput `pulumi:"logId"`
	// Lifecycle state of the log object
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetUnifiedAgentConfigurationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetUnifiedAgentConfigurationsArgs)(nil)).Elem()
}

// A collection of values returned by getUnifiedAgentConfigurations.
type GetUnifiedAgentConfigurationsResultOutput struct{ *pulumi.OutputState }

func (GetUnifiedAgentConfigurationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetUnifiedAgentConfigurationsResult)(nil)).Elem()
}

func (o GetUnifiedAgentConfigurationsResultOutput) ToGetUnifiedAgentConfigurationsResultOutput() GetUnifiedAgentConfigurationsResultOutput {
	return o
}

func (o GetUnifiedAgentConfigurationsResultOutput) ToGetUnifiedAgentConfigurationsResultOutputWithContext(ctx context.Context) GetUnifiedAgentConfigurationsResultOutput {
	return o
}

// The OCID of the compartment that the resource belongs to.
func (o GetUnifiedAgentConfigurationsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetUnifiedAgentConfigurationsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
func (o GetUnifiedAgentConfigurationsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetUnifiedAgentConfigurationsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetUnifiedAgentConfigurationsResultOutput) Filters() GetUnifiedAgentConfigurationsFilterArrayOutput {
	return o.ApplyT(func(v GetUnifiedAgentConfigurationsResult) []GetUnifiedAgentConfigurationsFilter { return v.Filters }).(GetUnifiedAgentConfigurationsFilterArrayOutput)
}

func (o GetUnifiedAgentConfigurationsResultOutput) GroupId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetUnifiedAgentConfigurationsResult) *string { return v.GroupId }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetUnifiedAgentConfigurationsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetUnifiedAgentConfigurationsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetUnifiedAgentConfigurationsResultOutput) IsCompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetUnifiedAgentConfigurationsResult) *bool { return v.IsCompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

func (o GetUnifiedAgentConfigurationsResultOutput) LogId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetUnifiedAgentConfigurationsResult) *string { return v.LogId }).(pulumi.StringPtrOutput)
}

// The pipeline state.
func (o GetUnifiedAgentConfigurationsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetUnifiedAgentConfigurationsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The list of unified_agent_configuration_collection.
func (o GetUnifiedAgentConfigurationsResultOutput) UnifiedAgentConfigurationCollections() GetUnifiedAgentConfigurationsUnifiedAgentConfigurationCollectionArrayOutput {
	return o.ApplyT(func(v GetUnifiedAgentConfigurationsResult) []GetUnifiedAgentConfigurationsUnifiedAgentConfigurationCollection {
		return v.UnifiedAgentConfigurationCollections
	}).(GetUnifiedAgentConfigurationsUnifiedAgentConfigurationCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetUnifiedAgentConfigurationsResultOutput{})
}