// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudbridge

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Agent Dependencies in Oracle Cloud Infrastructure Cloud Bridge service.
//
// Returns a list of AgentDependencies such as AgentDependencyCollection.
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
//			_, err := CloudBridge.GetAgentDependencies(ctx, &cloudbridge.GetAgentDependenciesArgs{
//				CompartmentId: _var.Compartment_id,
//				AgentId:       pulumi.StringRef(oci_cloud_bridge_agent.Test_agent.Id),
//				DisplayName:   pulumi.StringRef(_var.Agent_dependency_display_name),
//				EnvironmentId: pulumi.StringRef(oci_cloud_bridge_environment.Test_environment.Id),
//				State:         pulumi.StringRef(_var.Agent_dependency_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAgentDependencies(ctx *pulumi.Context, args *GetAgentDependenciesArgs, opts ...pulumi.InvokeOption) (*GetAgentDependenciesResult, error) {
	var rv GetAgentDependenciesResult
	err := ctx.Invoke("oci:CloudBridge/getAgentDependencies:getAgentDependencies", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAgentDependencies.
type GetAgentDependenciesArgs struct {
	// A filter to return only resources that match the given Agent ID.
	AgentId *string `pulumi:"agentId"`
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string `pulumi:"displayName"`
	// A filter to return only resources that match the given environment ID.
	EnvironmentId *string                      `pulumi:"environmentId"`
	Filters       []GetAgentDependenciesFilter `pulumi:"filters"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State *string `pulumi:"state"`
}

// A collection of values returned by getAgentDependencies.
type GetAgentDependenciesResult struct {
	// The list of agent_dependency_collection.
	AgentDependencyCollections []GetAgentDependenciesAgentDependencyCollection `pulumi:"agentDependencyCollections"`
	AgentId                    *string                                         `pulumi:"agentId"`
	// Compartment identifier
	CompartmentId string `pulumi:"compartmentId"`
	// Display name of the Agent dependency.
	DisplayName   *string                      `pulumi:"displayName"`
	EnvironmentId *string                      `pulumi:"environmentId"`
	Filters       []GetAgentDependenciesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of AgentDependency.
	State *string `pulumi:"state"`
}

func GetAgentDependenciesOutput(ctx *pulumi.Context, args GetAgentDependenciesOutputArgs, opts ...pulumi.InvokeOption) GetAgentDependenciesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetAgentDependenciesResult, error) {
			args := v.(GetAgentDependenciesArgs)
			r, err := GetAgentDependencies(ctx, &args, opts...)
			var s GetAgentDependenciesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetAgentDependenciesResultOutput)
}

// A collection of arguments for invoking getAgentDependencies.
type GetAgentDependenciesOutputArgs struct {
	// A filter to return only resources that match the given Agent ID.
	AgentId pulumi.StringPtrInput `pulumi:"agentId"`
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// A filter to return only resources that match the given environment ID.
	EnvironmentId pulumi.StringPtrInput                `pulumi:"environmentId"`
	Filters       GetAgentDependenciesFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetAgentDependenciesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAgentDependenciesArgs)(nil)).Elem()
}

// A collection of values returned by getAgentDependencies.
type GetAgentDependenciesResultOutput struct{ *pulumi.OutputState }

func (GetAgentDependenciesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAgentDependenciesResult)(nil)).Elem()
}

func (o GetAgentDependenciesResultOutput) ToGetAgentDependenciesResultOutput() GetAgentDependenciesResultOutput {
	return o
}

func (o GetAgentDependenciesResultOutput) ToGetAgentDependenciesResultOutputWithContext(ctx context.Context) GetAgentDependenciesResultOutput {
	return o
}

// The list of agent_dependency_collection.
func (o GetAgentDependenciesResultOutput) AgentDependencyCollections() GetAgentDependenciesAgentDependencyCollectionArrayOutput {
	return o.ApplyT(func(v GetAgentDependenciesResult) []GetAgentDependenciesAgentDependencyCollection {
		return v.AgentDependencyCollections
	}).(GetAgentDependenciesAgentDependencyCollectionArrayOutput)
}

func (o GetAgentDependenciesResultOutput) AgentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentDependenciesResult) *string { return v.AgentId }).(pulumi.StringPtrOutput)
}

// Compartment identifier
func (o GetAgentDependenciesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAgentDependenciesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Display name of the Agent dependency.
func (o GetAgentDependenciesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentDependenciesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetAgentDependenciesResultOutput) EnvironmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentDependenciesResult) *string { return v.EnvironmentId }).(pulumi.StringPtrOutput)
}

func (o GetAgentDependenciesResultOutput) Filters() GetAgentDependenciesFilterArrayOutput {
	return o.ApplyT(func(v GetAgentDependenciesResult) []GetAgentDependenciesFilter { return v.Filters }).(GetAgentDependenciesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAgentDependenciesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAgentDependenciesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of AgentDependency.
func (o GetAgentDependenciesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentDependenciesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAgentDependenciesResultOutput{})
}