// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package stackmonitoring

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Monitored Resource resource in Oracle Cloud Infrastructure Stack Monitoring service.
//
// Gets a monitored resource by identifier
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/StackMonitoring"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := StackMonitoring.GetMonitoredResource(ctx, &stackmonitoring.GetMonitoredResourceArgs{
// 			MonitoredResourceId: oci_stack_monitoring_monitored_resource.Test_monitored_resource.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupMonitoredResource(ctx *pulumi.Context, args *LookupMonitoredResourceArgs, opts ...pulumi.InvokeOption) (*LookupMonitoredResourceResult, error) {
	var rv LookupMonitoredResourceResult
	err := ctx.Invoke("oci:StackMonitoring/getMonitoredResource:getMonitoredResource", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMonitoredResource.
type LookupMonitoredResourceArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource.
	MonitoredResourceId string `pulumi:"monitoredResourceId"`
}

// A collection of values returned by getMonitoredResource.
type LookupMonitoredResourceResult struct {
	// Monitored Resource Alias Credential Details
	Aliases []GetMonitoredResourceAlias `pulumi:"aliases"`
	// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
	CompartmentId string `pulumi:"compartmentId"`
	// Monitored Resource Credential Details
	Credentials []GetMonitoredResourceCredential `pulumi:"credentials"`
	// Connection details to connect to the database. HostName, protocol, and port should be specified.
	DatabaseConnectionDetails []GetMonitoredResourceDatabaseConnectionDetail `pulumi:"databaseConnectionDetails"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Monitored resource display name.
	DisplayName        string `pulumi:"displayName"`
	ExternalResourceId string `pulumi:"externalResourceId"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Monitored resource host name.
	HostName string `pulumi:"hostName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource.
	Id string `pulumi:"id"`
	// Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ManagementAgentId   string `pulumi:"managementAgentId"`
	MonitoredResourceId string `pulumi:"monitoredResourceId"`
	// property name
	Name string `pulumi:"name"`
	// List of monitored resource properties
	Properties []GetMonitoredResourceProperty `pulumi:"properties"`
	// Time zone in the form of tz database canonical zone ID.
	ResourceTimeZone string `pulumi:"resourceTimeZone"`
	// Lifecycle state of the monitored resource.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
	TenantId string `pulumi:"tenantId"`
	// The time the the resource was created. An RFC3339 formatted datetime string
	TimeCreated string `pulumi:"timeCreated"`
	// The time the the resource was updated. An RFC3339 formatted datetime string
	TimeUpdated string `pulumi:"timeUpdated"`
	// Monitored resource type
	Type string `pulumi:"type"`
}

func LookupMonitoredResourceOutput(ctx *pulumi.Context, args LookupMonitoredResourceOutputArgs, opts ...pulumi.InvokeOption) LookupMonitoredResourceResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupMonitoredResourceResult, error) {
			args := v.(LookupMonitoredResourceArgs)
			r, err := LookupMonitoredResource(ctx, &args, opts...)
			var s LookupMonitoredResourceResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupMonitoredResourceResultOutput)
}

// A collection of arguments for invoking getMonitoredResource.
type LookupMonitoredResourceOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource.
	MonitoredResourceId pulumi.StringInput `pulumi:"monitoredResourceId"`
}

func (LookupMonitoredResourceOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMonitoredResourceArgs)(nil)).Elem()
}

// A collection of values returned by getMonitoredResource.
type LookupMonitoredResourceResultOutput struct{ *pulumi.OutputState }

func (LookupMonitoredResourceResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMonitoredResourceResult)(nil)).Elem()
}

func (o LookupMonitoredResourceResultOutput) ToLookupMonitoredResourceResultOutput() LookupMonitoredResourceResultOutput {
	return o
}

func (o LookupMonitoredResourceResultOutput) ToLookupMonitoredResourceResultOutputWithContext(ctx context.Context) LookupMonitoredResourceResultOutput {
	return o
}

// Monitored Resource Alias Credential Details
func (o LookupMonitoredResourceResultOutput) Aliases() GetMonitoredResourceAliasArrayOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) []GetMonitoredResourceAlias { return v.Aliases }).(GetMonitoredResourceAliasArrayOutput)
}

// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
func (o LookupMonitoredResourceResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Monitored Resource Credential Details
func (o LookupMonitoredResourceResultOutput) Credentials() GetMonitoredResourceCredentialArrayOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) []GetMonitoredResourceCredential { return v.Credentials }).(GetMonitoredResourceCredentialArrayOutput)
}

// Connection details to connect to the database. HostName, protocol, and port should be specified.
func (o LookupMonitoredResourceResultOutput) DatabaseConnectionDetails() GetMonitoredResourceDatabaseConnectionDetailArrayOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) []GetMonitoredResourceDatabaseConnectionDetail {
		return v.DatabaseConnectionDetails
	}).(GetMonitoredResourceDatabaseConnectionDetailArrayOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupMonitoredResourceResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Monitored resource display name.
func (o LookupMonitoredResourceResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

func (o LookupMonitoredResourceResultOutput) ExternalResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.ExternalResourceId }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupMonitoredResourceResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// Monitored resource host name.
func (o LookupMonitoredResourceResultOutput) HostName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.HostName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource.
func (o LookupMonitoredResourceResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.Id }).(pulumi.StringOutput)
}

// Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o LookupMonitoredResourceResultOutput) ManagementAgentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.ManagementAgentId }).(pulumi.StringOutput)
}

func (o LookupMonitoredResourceResultOutput) MonitoredResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.MonitoredResourceId }).(pulumi.StringOutput)
}

// property name
func (o LookupMonitoredResourceResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.Name }).(pulumi.StringOutput)
}

// List of monitored resource properties
func (o LookupMonitoredResourceResultOutput) Properties() GetMonitoredResourcePropertyArrayOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) []GetMonitoredResourceProperty { return v.Properties }).(GetMonitoredResourcePropertyArrayOutput)
}

// Time zone in the form of tz database canonical zone ID.
func (o LookupMonitoredResourceResultOutput) ResourceTimeZone() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.ResourceTimeZone }).(pulumi.StringOutput)
}

// Lifecycle state of the monitored resource.
func (o LookupMonitoredResourceResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupMonitoredResourceResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
func (o LookupMonitoredResourceResultOutput) TenantId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.TenantId }).(pulumi.StringOutput)
}

// The time the the resource was created. An RFC3339 formatted datetime string
func (o LookupMonitoredResourceResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the the resource was updated. An RFC3339 formatted datetime string
func (o LookupMonitoredResourceResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Monitored resource type
func (o LookupMonitoredResourceResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupMonitoredResourceResultOutput{})
}
