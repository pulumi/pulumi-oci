// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package kms

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides details about a specific Ekms Private Endpoint resource in Oracle Cloud Infrastructure Kms service.
//
// Gets a specific EKMS private by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Kms"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Kms.GetEkmsPrivateEndpoint(ctx, &kms.GetEkmsPrivateEndpointArgs{
//				EkmsPrivateEndpointId: oci_kms_ekms_private_endpoint.Test_ekms_private_endpoint.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupEkmsPrivateEndpoint(ctx *pulumi.Context, args *LookupEkmsPrivateEndpointArgs, opts ...pulumi.InvokeOption) (*LookupEkmsPrivateEndpointResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupEkmsPrivateEndpointResult
	err := ctx.Invoke("oci:Kms/getEkmsPrivateEndpoint:getEkmsPrivateEndpoint", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getEkmsPrivateEndpoint.
type LookupEkmsPrivateEndpointArgs struct {
	// Unique EKMS private endpoint identifier.
	EkmsPrivateEndpointId string `pulumi:"ekmsPrivateEndpointId"`
}

// A collection of values returned by getEkmsPrivateEndpoint.
type LookupEkmsPrivateEndpointResult struct {
	// CABundle to validate TLS certificate of the external key manager system in PEM format
	CaBundle string `pulumi:"caBundle"`
	// Identifier of the compartment this EKMS private endpoint belongs to
	CompartmentId string `pulumi:"compartmentId"`
	// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Mutable name of the EKMS private endpoint
	DisplayName           string `pulumi:"displayName"`
	EkmsPrivateEndpointId string `pulumi:"ekmsPrivateEndpointId"`
	// Private IP of the external key manager system to connect to from the EKMS private endpoint
	ExternalKeyManagerIp string `pulumi:"externalKeyManagerIp"`
	// Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Unique identifier that is immutable
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The port of the external key manager system
	Port int `pulumi:"port"`
	// The IP address in the customer's VCN for the EKMS private endpoint. This is taken from subnet
	PrivateEndpointIp string `pulumi:"privateEndpointIp"`
	// The current state of the EKMS private endpoint resource.
	State string `pulumi:"state"`
	// Subnet Identifier
	SubnetId string `pulumi:"subnetId"`
	// The time the EKMS private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time the EKMS private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupEkmsPrivateEndpointOutput(ctx *pulumi.Context, args LookupEkmsPrivateEndpointOutputArgs, opts ...pulumi.InvokeOption) LookupEkmsPrivateEndpointResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupEkmsPrivateEndpointResult, error) {
			args := v.(LookupEkmsPrivateEndpointArgs)
			r, err := LookupEkmsPrivateEndpoint(ctx, &args, opts...)
			var s LookupEkmsPrivateEndpointResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupEkmsPrivateEndpointResultOutput)
}

// A collection of arguments for invoking getEkmsPrivateEndpoint.
type LookupEkmsPrivateEndpointOutputArgs struct {
	// Unique EKMS private endpoint identifier.
	EkmsPrivateEndpointId pulumi.StringInput `pulumi:"ekmsPrivateEndpointId"`
}

func (LookupEkmsPrivateEndpointOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupEkmsPrivateEndpointArgs)(nil)).Elem()
}

// A collection of values returned by getEkmsPrivateEndpoint.
type LookupEkmsPrivateEndpointResultOutput struct{ *pulumi.OutputState }

func (LookupEkmsPrivateEndpointResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupEkmsPrivateEndpointResult)(nil)).Elem()
}

func (o LookupEkmsPrivateEndpointResultOutput) ToLookupEkmsPrivateEndpointResultOutput() LookupEkmsPrivateEndpointResultOutput {
	return o
}

func (o LookupEkmsPrivateEndpointResultOutput) ToLookupEkmsPrivateEndpointResultOutputWithContext(ctx context.Context) LookupEkmsPrivateEndpointResultOutput {
	return o
}

func (o LookupEkmsPrivateEndpointResultOutput) ToOutput(ctx context.Context) pulumix.Output[LookupEkmsPrivateEndpointResult] {
	return pulumix.Output[LookupEkmsPrivateEndpointResult]{
		OutputState: o.OutputState,
	}
}

// CABundle to validate TLS certificate of the external key manager system in PEM format
func (o LookupEkmsPrivateEndpointResultOutput) CaBundle() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.CaBundle }).(pulumi.StringOutput)
}

// Identifier of the compartment this EKMS private endpoint belongs to
func (o LookupEkmsPrivateEndpointResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupEkmsPrivateEndpointResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Mutable name of the EKMS private endpoint
func (o LookupEkmsPrivateEndpointResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

func (o LookupEkmsPrivateEndpointResultOutput) EkmsPrivateEndpointId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.EkmsPrivateEndpointId }).(pulumi.StringOutput)
}

// Private IP of the external key manager system to connect to from the EKMS private endpoint
func (o LookupEkmsPrivateEndpointResultOutput) ExternalKeyManagerIp() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.ExternalKeyManagerIp }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupEkmsPrivateEndpointResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// Unique identifier that is immutable
func (o LookupEkmsPrivateEndpointResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
func (o LookupEkmsPrivateEndpointResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The port of the external key manager system
func (o LookupEkmsPrivateEndpointResultOutput) Port() pulumi.IntOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) int { return v.Port }).(pulumi.IntOutput)
}

// The IP address in the customer's VCN for the EKMS private endpoint. This is taken from subnet
func (o LookupEkmsPrivateEndpointResultOutput) PrivateEndpointIp() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.PrivateEndpointIp }).(pulumi.StringOutput)
}

// The current state of the EKMS private endpoint resource.
func (o LookupEkmsPrivateEndpointResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.State }).(pulumi.StringOutput)
}

// Subnet Identifier
func (o LookupEkmsPrivateEndpointResultOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.SubnetId }).(pulumi.StringOutput)
}

// The time the EKMS private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
func (o LookupEkmsPrivateEndpointResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the EKMS private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
func (o LookupEkmsPrivateEndpointResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupEkmsPrivateEndpointResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupEkmsPrivateEndpointResultOutput{})
}