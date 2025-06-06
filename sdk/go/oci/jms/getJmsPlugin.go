// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package jms

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Jms Plugin resource in Oracle Cloud Infrastructure Jms service.
//
// Returns the JmsPlugin.
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
//			_, err := jms.GetJmsPlugin(ctx, &jms.GetJmsPluginArgs{
//				JmsPluginId: testJmsPluginOciJmsJmsPlugin.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupJmsPlugin(ctx *pulumi.Context, args *LookupJmsPluginArgs, opts ...pulumi.InvokeOption) (*LookupJmsPluginResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupJmsPluginResult
	err := ctx.Invoke("oci:Jms/getJmsPlugin:getJmsPlugin", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getJmsPlugin.
type LookupJmsPluginArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the JmsPlugin.
	JmsPluginId string `pulumi:"jmsPluginId"`
}

// A collection of values returned by getJmsPlugin.
type LookupJmsPluginResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Management Agent (OMA) or the Oracle Cloud Agent (OCA) instance where the JMS plugin is deployed.
	AgentId string `pulumi:"agentId"`
	// The agent type.
	AgentType string `pulumi:"agentType"`
	// The availability status.
	AvailabilityStatus string `pulumi:"availabilityStatus"`
	// The OMA/OCA agent's compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet.
	FleetId string `pulumi:"fleetId"`
	// Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`. (See [Managing Tags and Tag Namespaces](https://docs.cloud.oracle.com/iaas/Content/Tagging/Concepts/understandingfreeformtags.htm).)
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The hostname of the agent.
	Hostname string `pulumi:"hostname"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to identify this JmsPlugin.
	Id          string `pulumi:"id"`
	JmsPluginId string `pulumi:"jmsPluginId"`
	// The architecture of the operating system of the plugin.
	OsArchitecture string `pulumi:"osArchitecture"`
	// The distribution of the operating system of the plugin.
	OsDistribution string `pulumi:"osDistribution"`
	// The operating system family for the plugin.
	OsFamily string `pulumi:"osFamily"`
	// The version of the plugin.
	PluginVersion string `pulumi:"pluginVersion"`
	// The lifecycle state.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the resource was _last_ reported to JMS. This is potentially _after_ the specified time period provided by the filters. For example, a resource can be last reported to JMS before the start of a specified time period, if it is also reported during the time period.
	TimeLastSeen string `pulumi:"timeLastSeen"`
	// The date and time the plugin was registered.
	TimeRegistered string `pulumi:"timeRegistered"`
}

func LookupJmsPluginOutput(ctx *pulumi.Context, args LookupJmsPluginOutputArgs, opts ...pulumi.InvokeOption) LookupJmsPluginResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupJmsPluginResultOutput, error) {
			args := v.(LookupJmsPluginArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Jms/getJmsPlugin:getJmsPlugin", args, LookupJmsPluginResultOutput{}, options).(LookupJmsPluginResultOutput), nil
		}).(LookupJmsPluginResultOutput)
}

// A collection of arguments for invoking getJmsPlugin.
type LookupJmsPluginOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the JmsPlugin.
	JmsPluginId pulumi.StringInput `pulumi:"jmsPluginId"`
}

func (LookupJmsPluginOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupJmsPluginArgs)(nil)).Elem()
}

// A collection of values returned by getJmsPlugin.
type LookupJmsPluginResultOutput struct{ *pulumi.OutputState }

func (LookupJmsPluginResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupJmsPluginResult)(nil)).Elem()
}

func (o LookupJmsPluginResultOutput) ToLookupJmsPluginResultOutput() LookupJmsPluginResultOutput {
	return o
}

func (o LookupJmsPluginResultOutput) ToLookupJmsPluginResultOutputWithContext(ctx context.Context) LookupJmsPluginResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Management Agent (OMA) or the Oracle Cloud Agent (OCA) instance where the JMS plugin is deployed.
func (o LookupJmsPluginResultOutput) AgentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.AgentId }).(pulumi.StringOutput)
}

// The agent type.
func (o LookupJmsPluginResultOutput) AgentType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.AgentType }).(pulumi.StringOutput)
}

// The availability status.
func (o LookupJmsPluginResultOutput) AvailabilityStatus() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.AvailabilityStatus }).(pulumi.StringOutput)
}

// The OMA/OCA agent's compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o LookupJmsPluginResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
func (o LookupJmsPluginResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet.
func (o LookupJmsPluginResultOutput) FleetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.FleetId }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`. (See [Managing Tags and Tag Namespaces](https://docs.cloud.oracle.com/iaas/Content/Tagging/Concepts/understandingfreeformtags.htm).)
func (o LookupJmsPluginResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The hostname of the agent.
func (o LookupJmsPluginResultOutput) Hostname() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.Hostname }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to identify this JmsPlugin.
func (o LookupJmsPluginResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupJmsPluginResultOutput) JmsPluginId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.JmsPluginId }).(pulumi.StringOutput)
}

// The architecture of the operating system of the plugin.
func (o LookupJmsPluginResultOutput) OsArchitecture() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.OsArchitecture }).(pulumi.StringOutput)
}

// The distribution of the operating system of the plugin.
func (o LookupJmsPluginResultOutput) OsDistribution() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.OsDistribution }).(pulumi.StringOutput)
}

// The operating system family for the plugin.
func (o LookupJmsPluginResultOutput) OsFamily() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.OsFamily }).(pulumi.StringOutput)
}

// The version of the plugin.
func (o LookupJmsPluginResultOutput) PluginVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.PluginVersion }).(pulumi.StringOutput)
}

// The lifecycle state.
func (o LookupJmsPluginResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupJmsPluginResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the resource was _last_ reported to JMS. This is potentially _after_ the specified time period provided by the filters. For example, a resource can be last reported to JMS before the start of a specified time period, if it is also reported during the time period.
func (o LookupJmsPluginResultOutput) TimeLastSeen() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.TimeLastSeen }).(pulumi.StringOutput)
}

// The date and time the plugin was registered.
func (o LookupJmsPluginResultOutput) TimeRegistered() pulumi.StringOutput {
	return o.ApplyT(func(v LookupJmsPluginResult) string { return v.TimeRegistered }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupJmsPluginResultOutput{})
}
