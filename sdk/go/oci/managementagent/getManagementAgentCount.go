// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package managementagent

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Management Agent Count resource in Oracle Cloud Infrastructure Management Agent service.
//
// Gets count of the inventory of agents for a given compartment id, group by, and isPluginDeployed parameters.
// Supported groupBy parameters: availabilityStatus, platformType, version
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/ManagementAgent"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ManagementAgent.GetManagementAgentCount(ctx, &managementagent.GetManagementAgentCountArgs{
//				CompartmentId: _var.Compartment_id,
//				GroupBies:     _var.Management_agent_count_group_by,
//				HasPlugins:    pulumi.BoolRef(_var.Management_agent_count_has_plugins),
//				InstallType:   pulumi.StringRef(_var.Management_agent_count_install_type),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagementAgentCount(ctx *pulumi.Context, args *GetManagementAgentCountArgs, opts ...pulumi.InvokeOption) (*GetManagementAgentCountResult, error) {
	var rv GetManagementAgentCountResult
	err := ctx.Invoke("oci:ManagementAgent/getManagementAgentCount:getManagementAgentCount", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagementAgentCount.
type GetManagementAgentCountArgs struct {
	// The OCID of the compartment to which a request will be scoped.
	CompartmentId string `pulumi:"compartmentId"`
	// The field by which to group Management Agents. Currently, only one groupBy dimension is supported at a time.
	GroupBies []string `pulumi:"groupBies"`
	// When set to true then agents that have at least one plugin deployed will be returned. When set to false only agents that have no plugins deployed will be returned.
	HasPlugins *bool `pulumi:"hasPlugins"`
	// A filter to return either agents or gateway types depending upon install type selected by user. By default both install type will be returned.
	InstallType *string `pulumi:"installType"`
}

// A collection of values returned by getManagementAgentCount.
type GetManagementAgentCountResult struct {
	CompartmentId string   `pulumi:"compartmentId"`
	GroupBies     []string `pulumi:"groupBies"`
	// Whether or not a managementAgent has at least one plugin
	HasPlugins *bool `pulumi:"hasPlugins"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The install type, either AGENT or GATEWAY
	InstallType *string `pulumi:"installType"`
	// List in which each item describes an aggregation of Managment Agents
	Items []GetManagementAgentCountItem `pulumi:"items"`
}

func GetManagementAgentCountOutput(ctx *pulumi.Context, args GetManagementAgentCountOutputArgs, opts ...pulumi.InvokeOption) GetManagementAgentCountResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetManagementAgentCountResult, error) {
			args := v.(GetManagementAgentCountArgs)
			r, err := GetManagementAgentCount(ctx, &args, opts...)
			var s GetManagementAgentCountResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetManagementAgentCountResultOutput)
}

// A collection of arguments for invoking getManagementAgentCount.
type GetManagementAgentCountOutputArgs struct {
	// The OCID of the compartment to which a request will be scoped.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The field by which to group Management Agents. Currently, only one groupBy dimension is supported at a time.
	GroupBies pulumi.StringArrayInput `pulumi:"groupBies"`
	// When set to true then agents that have at least one plugin deployed will be returned. When set to false only agents that have no plugins deployed will be returned.
	HasPlugins pulumi.BoolPtrInput `pulumi:"hasPlugins"`
	// A filter to return either agents or gateway types depending upon install type selected by user. By default both install type will be returned.
	InstallType pulumi.StringPtrInput `pulumi:"installType"`
}

func (GetManagementAgentCountOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagementAgentCountArgs)(nil)).Elem()
}

// A collection of values returned by getManagementAgentCount.
type GetManagementAgentCountResultOutput struct{ *pulumi.OutputState }

func (GetManagementAgentCountResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagementAgentCountResult)(nil)).Elem()
}

func (o GetManagementAgentCountResultOutput) ToGetManagementAgentCountResultOutput() GetManagementAgentCountResultOutput {
	return o
}

func (o GetManagementAgentCountResultOutput) ToGetManagementAgentCountResultOutputWithContext(ctx context.Context) GetManagementAgentCountResultOutput {
	return o
}

func (o GetManagementAgentCountResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagementAgentCountResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetManagementAgentCountResultOutput) GroupBies() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetManagementAgentCountResult) []string { return v.GroupBies }).(pulumi.StringArrayOutput)
}

// Whether or not a managementAgent has at least one plugin
func (o GetManagementAgentCountResultOutput) HasPlugins() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetManagementAgentCountResult) *bool { return v.HasPlugins }).(pulumi.BoolPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagementAgentCountResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagementAgentCountResult) string { return v.Id }).(pulumi.StringOutput)
}

// The install type, either AGENT or GATEWAY
func (o GetManagementAgentCountResultOutput) InstallType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementAgentCountResult) *string { return v.InstallType }).(pulumi.StringPtrOutput)
}

// List in which each item describes an aggregation of Managment Agents
func (o GetManagementAgentCountResultOutput) Items() GetManagementAgentCountItemArrayOutput {
	return o.ApplyT(func(v GetManagementAgentCountResult) []GetManagementAgentCountItem { return v.Items }).(GetManagementAgentCountItemArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagementAgentCountResultOutput{})
}