// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package managementagent

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Management Agents in Oracle Cloud Infrastructure Management Agent service.
//
// Returns a list of Management Agents.
// If no explicit page size limit is specified, it will default to 1000 when compartmentIdInSubtree is true and 5000 otherwise.
// The response is limited to maximum 1000 records when compartmentIdInSubtree is true.
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
//			_, err := ManagementAgent.GetManagementAgents(ctx, &managementagent.GetManagementAgentsArgs{
//				CompartmentId:          _var.Compartment_id,
//				AccessLevel:            pulumi.StringRef(_var.Management_agent_access_level),
//				AvailabilityStatus:     pulumi.StringRef(_var.Management_agent_availability_status),
//				CompartmentIdInSubtree: pulumi.BoolRef(_var.Management_agent_compartment_id_in_subtree),
//				DisplayName:            pulumi.StringRef(_var.Management_agent_display_name),
//				HostId:                 pulumi.StringRef(oci_management_agent_host.Test_host.Id),
//				InstallType:            pulumi.StringRef(_var.Management_agent_install_type),
//				IsCustomerDeployed:     pulumi.BoolRef(_var.Management_agent_is_customer_deployed),
//				PlatformTypes:          _var.Management_agent_platform_type,
//				PluginNames:            _var.Management_agent_plugin_name,
//				State:                  pulumi.StringRef(_var.Management_agent_state),
//				Versions:               _var.Management_agent_version,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagementAgents(ctx *pulumi.Context, args *GetManagementAgentsArgs, opts ...pulumi.InvokeOption) (*GetManagementAgentsResult, error) {
	var rv GetManagementAgentsResult
	err := ctx.Invoke("oci:ManagementAgent/getManagementAgents:getManagementAgents", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagementAgents.
type GetManagementAgentsArgs struct {
	// When the value is "ACCESSIBLE", insufficient permissions for a compartment will filter out resources in that compartment without rejecting the request.
	AccessLevel *string `pulumi:"accessLevel"`
	// Filter to return only Management Agents in the particular availability status.
	AvailabilityStatus *string `pulumi:"availabilityStatus"`
	// The OCID of the compartment to which a request will be scoped.
	CompartmentId string `pulumi:"compartmentId"`
	// if set to true then it fetches resources for all compartments where user has access to else only on the compartment specified.
	CompartmentIdInSubtree *bool `pulumi:"compartmentIdInSubtree"`
	// Filter to return only Management Agents having the particular display name.
	DisplayName *string                     `pulumi:"displayName"`
	Filters     []GetManagementAgentsFilter `pulumi:"filters"`
	// Filter to return only Management Agents having the particular agent host id.
	HostId *string `pulumi:"hostId"`
	// A filter to return either agents or gateway types depending upon install type selected by user. By default both install type will be returned.
	InstallType *string `pulumi:"installType"`
	// true, if the agent image is manually downloaded and installed. false, if the agent is deployed as a plugin in Oracle Cloud Agent.
	IsCustomerDeployed *bool `pulumi:"isCustomerDeployed"`
	// Array of PlatformTypes to return only results having the particular platform types. Example: ["LINUX"]
	PlatformTypes []string `pulumi:"platformTypes"`
	// Array of pluginName to return only Management Agents having the particular Plugins installed. A special pluginName of 'None' can be provided and this will return only Management Agents having no plugin installed. Example: ["PluginA"]
	PluginNames []string `pulumi:"pluginNames"`
	// Filter to return only Management Agents in the particular lifecycle state.
	State *string `pulumi:"state"`
	// Array of versions to return only Management Agents having the particular agent versions. Example: ["202020.0101","210201.0513"]
	Versions []string `pulumi:"versions"`
}

// A collection of values returned by getManagementAgents.
type GetManagementAgentsResult struct {
	AccessLevel *string `pulumi:"accessLevel"`
	// The current availability status of managementAgent
	AvailabilityStatus *string `pulumi:"availabilityStatus"`
	// Compartment Identifier
	CompartmentId          string `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool  `pulumi:"compartmentIdInSubtree"`
	// Management Agent Name
	DisplayName *string                     `pulumi:"displayName"`
	Filters     []GetManagementAgentsFilter `pulumi:"filters"`
	// Host resource ocid
	HostId *string `pulumi:"hostId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The install type, either AGENT or GATEWAY
	InstallType *string `pulumi:"installType"`
	// true, if the agent image is manually downloaded and installed. false, if the agent is deployed as a plugin in Oracle Cloud Agent.
	IsCustomerDeployed *bool `pulumi:"isCustomerDeployed"`
	// The list of management_agents.
	ManagementAgents []GetManagementAgentsManagementAgent `pulumi:"managementAgents"`
	// Platform Type
	PlatformTypes []string `pulumi:"platformTypes"`
	// Management Agent Plugin Name
	PluginNames []string `pulumi:"pluginNames"`
	// The current state of managementAgent
	State *string `pulumi:"state"`
	// Management Agent Version
	Versions []string `pulumi:"versions"`
}

func GetManagementAgentsOutput(ctx *pulumi.Context, args GetManagementAgentsOutputArgs, opts ...pulumi.InvokeOption) GetManagementAgentsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetManagementAgentsResult, error) {
			args := v.(GetManagementAgentsArgs)
			r, err := GetManagementAgents(ctx, &args, opts...)
			var s GetManagementAgentsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetManagementAgentsResultOutput)
}

// A collection of arguments for invoking getManagementAgents.
type GetManagementAgentsOutputArgs struct {
	// When the value is "ACCESSIBLE", insufficient permissions for a compartment will filter out resources in that compartment without rejecting the request.
	AccessLevel pulumi.StringPtrInput `pulumi:"accessLevel"`
	// Filter to return only Management Agents in the particular availability status.
	AvailabilityStatus pulumi.StringPtrInput `pulumi:"availabilityStatus"`
	// The OCID of the compartment to which a request will be scoped.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// if set to true then it fetches resources for all compartments where user has access to else only on the compartment specified.
	CompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"compartmentIdInSubtree"`
	// Filter to return only Management Agents having the particular display name.
	DisplayName pulumi.StringPtrInput               `pulumi:"displayName"`
	Filters     GetManagementAgentsFilterArrayInput `pulumi:"filters"`
	// Filter to return only Management Agents having the particular agent host id.
	HostId pulumi.StringPtrInput `pulumi:"hostId"`
	// A filter to return either agents or gateway types depending upon install type selected by user. By default both install type will be returned.
	InstallType pulumi.StringPtrInput `pulumi:"installType"`
	// true, if the agent image is manually downloaded and installed. false, if the agent is deployed as a plugin in Oracle Cloud Agent.
	IsCustomerDeployed pulumi.BoolPtrInput `pulumi:"isCustomerDeployed"`
	// Array of PlatformTypes to return only results having the particular platform types. Example: ["LINUX"]
	PlatformTypes pulumi.StringArrayInput `pulumi:"platformTypes"`
	// Array of pluginName to return only Management Agents having the particular Plugins installed. A special pluginName of 'None' can be provided and this will return only Management Agents having no plugin installed. Example: ["PluginA"]
	PluginNames pulumi.StringArrayInput `pulumi:"pluginNames"`
	// Filter to return only Management Agents in the particular lifecycle state.
	State pulumi.StringPtrInput `pulumi:"state"`
	// Array of versions to return only Management Agents having the particular agent versions. Example: ["202020.0101","210201.0513"]
	Versions pulumi.StringArrayInput `pulumi:"versions"`
}

func (GetManagementAgentsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagementAgentsArgs)(nil)).Elem()
}

// A collection of values returned by getManagementAgents.
type GetManagementAgentsResultOutput struct{ *pulumi.OutputState }

func (GetManagementAgentsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagementAgentsResult)(nil)).Elem()
}

func (o GetManagementAgentsResultOutput) ToGetManagementAgentsResultOutput() GetManagementAgentsResultOutput {
	return o
}

func (o GetManagementAgentsResultOutput) ToGetManagementAgentsResultOutputWithContext(ctx context.Context) GetManagementAgentsResultOutput {
	return o
}

func (o GetManagementAgentsResultOutput) AccessLevel() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) *string { return v.AccessLevel }).(pulumi.StringPtrOutput)
}

// The current availability status of managementAgent
func (o GetManagementAgentsResultOutput) AvailabilityStatus() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) *string { return v.AvailabilityStatus }).(pulumi.StringPtrOutput)
}

// Compartment Identifier
func (o GetManagementAgentsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetManagementAgentsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// Management Agent Name
func (o GetManagementAgentsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetManagementAgentsResultOutput) Filters() GetManagementAgentsFilterArrayOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) []GetManagementAgentsFilter { return v.Filters }).(GetManagementAgentsFilterArrayOutput)
}

// Host resource ocid
func (o GetManagementAgentsResultOutput) HostId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) *string { return v.HostId }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagementAgentsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The install type, either AGENT or GATEWAY
func (o GetManagementAgentsResultOutput) InstallType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) *string { return v.InstallType }).(pulumi.StringPtrOutput)
}

// true, if the agent image is manually downloaded and installed. false, if the agent is deployed as a plugin in Oracle Cloud Agent.
func (o GetManagementAgentsResultOutput) IsCustomerDeployed() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) *bool { return v.IsCustomerDeployed }).(pulumi.BoolPtrOutput)
}

// The list of management_agents.
func (o GetManagementAgentsResultOutput) ManagementAgents() GetManagementAgentsManagementAgentArrayOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) []GetManagementAgentsManagementAgent { return v.ManagementAgents }).(GetManagementAgentsManagementAgentArrayOutput)
}

// Platform Type
func (o GetManagementAgentsResultOutput) PlatformTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) []string { return v.PlatformTypes }).(pulumi.StringArrayOutput)
}

// Management Agent Plugin Name
func (o GetManagementAgentsResultOutput) PluginNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) []string { return v.PluginNames }).(pulumi.StringArrayOutput)
}

// The current state of managementAgent
func (o GetManagementAgentsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// Management Agent Version
func (o GetManagementAgentsResultOutput) Versions() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetManagementAgentsResult) []string { return v.Versions }).(pulumi.StringArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagementAgentsResultOutput{})
}