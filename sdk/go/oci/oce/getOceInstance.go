// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package oce

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Oce Instance resource in Oracle Cloud Infrastructure Content and Experience service.
//
// # Gets a OceInstance by identifier
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Oce"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Oce.GetOceInstance(ctx, &oce.GetOceInstanceArgs{
//				OceInstanceId: oci_oce_oce_instance.Test_oce_instance.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetOceInstance(ctx *pulumi.Context, args *GetOceInstanceArgs, opts ...pulumi.InvokeOption) (*GetOceInstanceResult, error) {
	var rv GetOceInstanceResult
	err := ctx.Invoke("oci:Oce/getOceInstance:getOceInstance", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOceInstance.
type GetOceInstanceArgs struct {
	// unique OceInstance identifier
	OceInstanceId string `pulumi:"oceInstanceId"`
}

// A collection of values returned by getOceInstance.
type GetOceInstanceResult struct {
	// a list of add-on features for the ocm instance
	AddOnFeatures []string `pulumi:"addOnFeatures"`
	// Admin Email for Notification
	AdminEmail string `pulumi:"adminEmail"`
	// Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// OceInstance description, can be updated
	Description string `pulumi:"description"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Unique GUID identifier that is immutable on creation
	Guid string `pulumi:"guid"`
	// Unique identifier that is immutable on creation
	Id              string `pulumi:"id"`
	IdcsAccessToken string `pulumi:"idcsAccessToken"`
	// IDCS Tenancy Identifier
	IdcsTenancy string `pulumi:"idcsTenancy"`
	// Flag indicating whether the instance access is private or public
	InstanceAccessType string `pulumi:"instanceAccessType"`
	// Flag indicating whether the instance license is new cloud or bring your own license
	InstanceLicenseType string `pulumi:"instanceLicenseType"`
	// Instance type based on its usage
	InstanceUsageType string `pulumi:"instanceUsageType"`
	// Details of the current state of the instance lifecycle
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// OceInstance Name
	Name string `pulumi:"name"`
	// Object Storage Namespace of tenancy
	ObjectStorageNamespace string `pulumi:"objectStorageNamespace"`
	OceInstanceId          string `pulumi:"oceInstanceId"`
	// SERVICE data. Example: `{"service": {"IDCS": "value"}}`
	Service map[string]interface{} `pulumi:"service"`
	// The current state of the instance lifecycle.
	State string `pulumi:"state"`
	// An message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	StateMessage string `pulumi:"stateMessage"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// Tenancy Identifier
	TenancyId string `pulumi:"tenancyId"`
	// Tenancy Name
	TenancyName string `pulumi:"tenancyName"`
	// The time the the OceInstance was created. An RFC3339 formatted datetime string
	TimeCreated string `pulumi:"timeCreated"`
	// The time the OceInstance was updated. An RFC3339 formatted datetime string
	TimeUpdated string `pulumi:"timeUpdated"`
	// Upgrade schedule type representing service to be upgraded immediately whenever latest version is released or delay upgrade of the service to previous released version
	UpgradeSchedule string `pulumi:"upgradeSchedule"`
	// Web Application Firewall(WAF) primary domain
	WafPrimaryDomain string `pulumi:"wafPrimaryDomain"`
}

func GetOceInstanceOutput(ctx *pulumi.Context, args GetOceInstanceOutputArgs, opts ...pulumi.InvokeOption) GetOceInstanceResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetOceInstanceResult, error) {
			args := v.(GetOceInstanceArgs)
			r, err := GetOceInstance(ctx, &args, opts...)
			var s GetOceInstanceResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetOceInstanceResultOutput)
}

// A collection of arguments for invoking getOceInstance.
type GetOceInstanceOutputArgs struct {
	// unique OceInstance identifier
	OceInstanceId pulumi.StringInput `pulumi:"oceInstanceId"`
}

func (GetOceInstanceOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOceInstanceArgs)(nil)).Elem()
}

// A collection of values returned by getOceInstance.
type GetOceInstanceResultOutput struct{ *pulumi.OutputState }

func (GetOceInstanceResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOceInstanceResult)(nil)).Elem()
}

func (o GetOceInstanceResultOutput) ToGetOceInstanceResultOutput() GetOceInstanceResultOutput {
	return o
}

func (o GetOceInstanceResultOutput) ToGetOceInstanceResultOutputWithContext(ctx context.Context) GetOceInstanceResultOutput {
	return o
}

// a list of add-on features for the ocm instance
func (o GetOceInstanceResultOutput) AddOnFeatures() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetOceInstanceResult) []string { return v.AddOnFeatures }).(pulumi.StringArrayOutput)
}

// Admin Email for Notification
func (o GetOceInstanceResultOutput) AdminEmail() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.AdminEmail }).(pulumi.StringOutput)
}

// Compartment Identifier
func (o GetOceInstanceResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
func (o GetOceInstanceResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetOceInstanceResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// OceInstance description, can be updated
func (o GetOceInstanceResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.Description }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o GetOceInstanceResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetOceInstanceResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// Unique GUID identifier that is immutable on creation
func (o GetOceInstanceResultOutput) Guid() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.Guid }).(pulumi.StringOutput)
}

// Unique identifier that is immutable on creation
func (o GetOceInstanceResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetOceInstanceResultOutput) IdcsAccessToken() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.IdcsAccessToken }).(pulumi.StringOutput)
}

// IDCS Tenancy Identifier
func (o GetOceInstanceResultOutput) IdcsTenancy() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.IdcsTenancy }).(pulumi.StringOutput)
}

// Flag indicating whether the instance access is private or public
func (o GetOceInstanceResultOutput) InstanceAccessType() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.InstanceAccessType }).(pulumi.StringOutput)
}

// Flag indicating whether the instance license is new cloud or bring your own license
func (o GetOceInstanceResultOutput) InstanceLicenseType() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.InstanceLicenseType }).(pulumi.StringOutput)
}

// Instance type based on its usage
func (o GetOceInstanceResultOutput) InstanceUsageType() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.InstanceUsageType }).(pulumi.StringOutput)
}

// Details of the current state of the instance lifecycle
func (o GetOceInstanceResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// OceInstance Name
func (o GetOceInstanceResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.Name }).(pulumi.StringOutput)
}

// Object Storage Namespace of tenancy
func (o GetOceInstanceResultOutput) ObjectStorageNamespace() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.ObjectStorageNamespace }).(pulumi.StringOutput)
}

func (o GetOceInstanceResultOutput) OceInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.OceInstanceId }).(pulumi.StringOutput)
}

// SERVICE data. Example: `{"service": {"IDCS": "value"}}`
func (o GetOceInstanceResultOutput) Service() pulumi.MapOutput {
	return o.ApplyT(func(v GetOceInstanceResult) map[string]interface{} { return v.Service }).(pulumi.MapOutput)
}

// The current state of the instance lifecycle.
func (o GetOceInstanceResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.State }).(pulumi.StringOutput)
}

// An message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o GetOceInstanceResultOutput) StateMessage() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.StateMessage }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o GetOceInstanceResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetOceInstanceResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// Tenancy Identifier
func (o GetOceInstanceResultOutput) TenancyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.TenancyId }).(pulumi.StringOutput)
}

// Tenancy Name
func (o GetOceInstanceResultOutput) TenancyName() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.TenancyName }).(pulumi.StringOutput)
}

// The time the the OceInstance was created. An RFC3339 formatted datetime string
func (o GetOceInstanceResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the OceInstance was updated. An RFC3339 formatted datetime string
func (o GetOceInstanceResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Upgrade schedule type representing service to be upgraded immediately whenever latest version is released or delay upgrade of the service to previous released version
func (o GetOceInstanceResultOutput) UpgradeSchedule() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.UpgradeSchedule }).(pulumi.StringOutput)
}

// Web Application Firewall(WAF) primary domain
func (o GetOceInstanceResultOutput) WafPrimaryDomain() pulumi.StringOutput {
	return o.ApplyT(func(v GetOceInstanceResult) string { return v.WafPrimaryDomain }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetOceInstanceResultOutput{})
}