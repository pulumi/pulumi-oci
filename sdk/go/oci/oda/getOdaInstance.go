// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package oda

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Oda Instance resource in Oracle Cloud Infrastructure Digital Assistant service.
//
// Gets the specified Digital Assistant instance.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Oda"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Oda.GetOdaInstance(ctx, &oda.GetOdaInstanceArgs{
//				OdaInstanceId: oci_oda_oda_instance.Test_oda_instance.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupOdaInstance(ctx *pulumi.Context, args *LookupOdaInstanceArgs, opts ...pulumi.InvokeOption) (*LookupOdaInstanceResult, error) {
	var rv LookupOdaInstanceResult
	err := ctx.Invoke("oci:Oda/getOdaInstance:getOdaInstance", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOdaInstance.
type LookupOdaInstanceArgs struct {
	// Unique Digital Assistant instance identifier.
	OdaInstanceId string `pulumi:"odaInstanceId"`
}

// A collection of values returned by getOdaInstance.
type LookupOdaInstanceResult struct {
	// A list of attachment identifiers for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
	AttachmentIds []string `pulumi:"attachmentIds"`
	// A list of attachment types for this instance (if any). Use attachmentIds to get the details of the attachments.
	AttachmentTypes []string `pulumi:"attachmentTypes"`
	// Identifier of the compartment that the instance belongs to.
	CompartmentId string `pulumi:"compartmentId"`
	// URL for the connector's endpoint.
	ConnectorUrl string `pulumi:"connectorUrl"`
	// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Description of the Digital Assistant instance.
	Description string `pulumi:"description"`
	// User-defined name for the Digital Assistant instance. Avoid entering confidential information. You can change this value.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Unique immutable identifier that was assigned when the instance was created.
	Id string `pulumi:"id"`
	// If isRoleBasedAccess is set to true, this property specifies the URL for the administration console used to manage the Identity Application instance Digital Assistant has created inside the user-specified identity domain.
	IdentityAppConsoleUrl string `pulumi:"identityAppConsoleUrl"`
	// If isRoleBasedAccess is set to true, this property specifies the GUID of the Identity Application instance Digital Assistant has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this Digital Assistant instance for users within the identity domain.
	IdentityAppGuid string `pulumi:"identityAppGuid"`
	// If isRoleBasedAccess is set to true, this property specifies the identity domain that is to be used to implement this type of authorzation. Digital Assistant will create an Identity Application instance and Application Roles within this identity domain. The caller may then perform and user roll mappings they like to grant access to users within the identity domain.
	IdentityDomain string `pulumi:"identityDomain"`
	// A list of package ids imported into this instance (if any). Use GetImportedPackage to get the details of the imported packages.
	ImportedPackageIds []string `pulumi:"importedPackageIds"`
	// A list of package names imported into this instance (if any). Use importedPackageIds field to get the details of the imported packages.
	ImportedPackageNames []string `pulumi:"importedPackageNames"`
	// Should this Digital Assistant instance use role-based authorization via an identity domain (true) or use the default policy-based authorization via IAM policies (false)
	IsRoleBasedAccess bool `pulumi:"isRoleBasedAccess"`
	// The current sub-state of the Digital Assistant instance.
	LifecycleSubState string `pulumi:"lifecycleSubState"`
	OdaInstanceId     string `pulumi:"odaInstanceId"`
	// A list of restricted operations (across all attachments) for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
	RestrictedOperations []GetOdaInstanceRestrictedOperation `pulumi:"restrictedOperations"`
	// Shape or size of the instance.
	ShapeName string `pulumi:"shapeName"`
	// The current state of the Digital Assistant instance.
	State string `pulumi:"state"`
	// A message that describes the current state in more detail. For example, actionable information about an instance that's in the `FAILED` state.
	StateMessage string `pulumi:"stateMessage"`
	// When the Digital Assistant instance was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
	TimeCreated string `pulumi:"timeCreated"`
	// When the Digital Assistance instance was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
	TimeUpdated string `pulumi:"timeUpdated"`
	// URL for the Digital Assistant web application that's associated with the instance.
	WebAppUrl string `pulumi:"webAppUrl"`
}

func LookupOdaInstanceOutput(ctx *pulumi.Context, args LookupOdaInstanceOutputArgs, opts ...pulumi.InvokeOption) LookupOdaInstanceResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupOdaInstanceResult, error) {
			args := v.(LookupOdaInstanceArgs)
			r, err := LookupOdaInstance(ctx, &args, opts...)
			var s LookupOdaInstanceResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupOdaInstanceResultOutput)
}

// A collection of arguments for invoking getOdaInstance.
type LookupOdaInstanceOutputArgs struct {
	// Unique Digital Assistant instance identifier.
	OdaInstanceId pulumi.StringInput `pulumi:"odaInstanceId"`
}

func (LookupOdaInstanceOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupOdaInstanceArgs)(nil)).Elem()
}

// A collection of values returned by getOdaInstance.
type LookupOdaInstanceResultOutput struct{ *pulumi.OutputState }

func (LookupOdaInstanceResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupOdaInstanceResult)(nil)).Elem()
}

func (o LookupOdaInstanceResultOutput) ToLookupOdaInstanceResultOutput() LookupOdaInstanceResultOutput {
	return o
}

func (o LookupOdaInstanceResultOutput) ToLookupOdaInstanceResultOutputWithContext(ctx context.Context) LookupOdaInstanceResultOutput {
	return o
}

// A list of attachment identifiers for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
func (o LookupOdaInstanceResultOutput) AttachmentIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) []string { return v.AttachmentIds }).(pulumi.StringArrayOutput)
}

// A list of attachment types for this instance (if any). Use attachmentIds to get the details of the attachments.
func (o LookupOdaInstanceResultOutput) AttachmentTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) []string { return v.AttachmentTypes }).(pulumi.StringArrayOutput)
}

// Identifier of the compartment that the instance belongs to.
func (o LookupOdaInstanceResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// URL for the connector's endpoint.
func (o LookupOdaInstanceResultOutput) ConnectorUrl() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.ConnectorUrl }).(pulumi.StringOutput)
}

// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupOdaInstanceResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Description of the Digital Assistant instance.
func (o LookupOdaInstanceResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.Description }).(pulumi.StringOutput)
}

// User-defined name for the Digital Assistant instance. Avoid entering confidential information. You can change this value.
func (o LookupOdaInstanceResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
func (o LookupOdaInstanceResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// Unique immutable identifier that was assigned when the instance was created.
func (o LookupOdaInstanceResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.Id }).(pulumi.StringOutput)
}

// If isRoleBasedAccess is set to true, this property specifies the URL for the administration console used to manage the Identity Application instance Digital Assistant has created inside the user-specified identity domain.
func (o LookupOdaInstanceResultOutput) IdentityAppConsoleUrl() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.IdentityAppConsoleUrl }).(pulumi.StringOutput)
}

// If isRoleBasedAccess is set to true, this property specifies the GUID of the Identity Application instance Digital Assistant has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this Digital Assistant instance for users within the identity domain.
func (o LookupOdaInstanceResultOutput) IdentityAppGuid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.IdentityAppGuid }).(pulumi.StringOutput)
}

// If isRoleBasedAccess is set to true, this property specifies the identity domain that is to be used to implement this type of authorzation. Digital Assistant will create an Identity Application instance and Application Roles within this identity domain. The caller may then perform and user roll mappings they like to grant access to users within the identity domain.
func (o LookupOdaInstanceResultOutput) IdentityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.IdentityDomain }).(pulumi.StringOutput)
}

// A list of package ids imported into this instance (if any). Use GetImportedPackage to get the details of the imported packages.
func (o LookupOdaInstanceResultOutput) ImportedPackageIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) []string { return v.ImportedPackageIds }).(pulumi.StringArrayOutput)
}

// A list of package names imported into this instance (if any). Use importedPackageIds field to get the details of the imported packages.
func (o LookupOdaInstanceResultOutput) ImportedPackageNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) []string { return v.ImportedPackageNames }).(pulumi.StringArrayOutput)
}

// Should this Digital Assistant instance use role-based authorization via an identity domain (true) or use the default policy-based authorization via IAM policies (false)
func (o LookupOdaInstanceResultOutput) IsRoleBasedAccess() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) bool { return v.IsRoleBasedAccess }).(pulumi.BoolOutput)
}

// The current sub-state of the Digital Assistant instance.
func (o LookupOdaInstanceResultOutput) LifecycleSubState() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.LifecycleSubState }).(pulumi.StringOutput)
}

func (o LookupOdaInstanceResultOutput) OdaInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.OdaInstanceId }).(pulumi.StringOutput)
}

// A list of restricted operations (across all attachments) for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
func (o LookupOdaInstanceResultOutput) RestrictedOperations() GetOdaInstanceRestrictedOperationArrayOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) []GetOdaInstanceRestrictedOperation { return v.RestrictedOperations }).(GetOdaInstanceRestrictedOperationArrayOutput)
}

// Shape or size of the instance.
func (o LookupOdaInstanceResultOutput) ShapeName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.ShapeName }).(pulumi.StringOutput)
}

// The current state of the Digital Assistant instance.
func (o LookupOdaInstanceResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.State }).(pulumi.StringOutput)
}

// A message that describes the current state in more detail. For example, actionable information about an instance that's in the `FAILED` state.
func (o LookupOdaInstanceResultOutput) StateMessage() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.StateMessage }).(pulumi.StringOutput)
}

// When the Digital Assistant instance was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
func (o LookupOdaInstanceResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// When the Digital Assistance instance was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
func (o LookupOdaInstanceResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// URL for the Digital Assistant web application that's associated with the instance.
func (o LookupOdaInstanceResultOutput) WebAppUrl() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOdaInstanceResult) string { return v.WebAppUrl }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupOdaInstanceResultOutput{})
}