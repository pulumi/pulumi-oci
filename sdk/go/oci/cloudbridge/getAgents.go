// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudbridge

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Agents in Oracle Cloud Infrastructure Cloud Bridge service.
//
// Returns a list of Agents.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/CloudBridge"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := CloudBridge.GetAgents(ctx, &cloudbridge.GetAgentsArgs{
//				CompartmentId: _var.Compartment_id,
//				AgentId:       pulumi.StringRef(oci_cloud_bridge_agent.Test_agent.Id),
//				DisplayName:   pulumi.StringRef(_var.Agent_display_name),
//				EnvironmentId: pulumi.StringRef(oci_cloud_bridge_environment.Test_environment.Id),
//				State:         pulumi.StringRef(_var.Agent_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAgents(ctx *pulumi.Context, args *GetAgentsArgs, opts ...pulumi.InvokeOption) (*GetAgentsResult, error) {
	var rv GetAgentsResult
	err := ctx.Invoke("oci:CloudBridge/getAgents:getAgents", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAgents.
type GetAgentsArgs struct {
	// A filter to return only resources that match the given Agent ID.
	AgentId *string `pulumi:"agentId"`
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string `pulumi:"displayName"`
	// A filter to return only resources that match the given environment ID.
	EnvironmentId *string           `pulumi:"environmentId"`
	Filters       []GetAgentsFilter `pulumi:"filters"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State *string `pulumi:"state"`
}

// A collection of values returned by getAgents.
type GetAgentsResult struct {
	// The list of agent_collection.
	AgentCollections []GetAgentsAgentCollection `pulumi:"agentCollections"`
	// Agent identifier.
	AgentId *string `pulumi:"agentId"`
	// Compartment identifier.
	CompartmentId string `pulumi:"compartmentId"`
	// Agent identifier, can be renamed.
	DisplayName *string `pulumi:"displayName"`
	// Environment identifier.
	EnvironmentId *string           `pulumi:"environmentId"`
	Filters       []GetAgentsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the Agent.
	State *string `pulumi:"state"`
}

func GetAgentsOutput(ctx *pulumi.Context, args GetAgentsOutputArgs, opts ...pulumi.InvokeOption) GetAgentsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetAgentsResult, error) {
			args := v.(GetAgentsArgs)
			r, err := GetAgents(ctx, &args, opts...)
			var s GetAgentsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetAgentsResultOutput)
}

// A collection of arguments for invoking getAgents.
type GetAgentsOutputArgs struct {
	// A filter to return only resources that match the given Agent ID.
	AgentId pulumi.StringPtrInput `pulumi:"agentId"`
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// A filter to return only resources that match the given environment ID.
	EnvironmentId pulumi.StringPtrInput     `pulumi:"environmentId"`
	Filters       GetAgentsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetAgentsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAgentsArgs)(nil)).Elem()
}

// A collection of values returned by getAgents.
type GetAgentsResultOutput struct{ *pulumi.OutputState }

func (GetAgentsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAgentsResult)(nil)).Elem()
}

func (o GetAgentsResultOutput) ToGetAgentsResultOutput() GetAgentsResultOutput {
	return o
}

func (o GetAgentsResultOutput) ToGetAgentsResultOutputWithContext(ctx context.Context) GetAgentsResultOutput {
	return o
}

// The list of agent_collection.
func (o GetAgentsResultOutput) AgentCollections() GetAgentsAgentCollectionArrayOutput {
	return o.ApplyT(func(v GetAgentsResult) []GetAgentsAgentCollection { return v.AgentCollections }).(GetAgentsAgentCollectionArrayOutput)
}

// Agent identifier.
func (o GetAgentsResultOutput) AgentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentsResult) *string { return v.AgentId }).(pulumi.StringPtrOutput)
}

// Compartment identifier.
func (o GetAgentsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAgentsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Agent identifier, can be renamed.
func (o GetAgentsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// Environment identifier.
func (o GetAgentsResultOutput) EnvironmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentsResult) *string { return v.EnvironmentId }).(pulumi.StringPtrOutput)
}

func (o GetAgentsResultOutput) Filters() GetAgentsFilterArrayOutput {
	return o.ApplyT(func(v GetAgentsResult) []GetAgentsFilter { return v.Filters }).(GetAgentsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAgentsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAgentsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the Agent.
func (o GetAgentsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAgentsResultOutput{})
}