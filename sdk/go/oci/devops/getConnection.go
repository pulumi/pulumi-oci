// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Connection resource in Oracle Cloud Infrastructure Devops service.
//
// Retrieves a connection by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DevOps"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DevOps.GetConnection(ctx, &devops.GetConnectionArgs{
//				ConnectionId: oci_devops_connection.Test_connection.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupConnection(ctx *pulumi.Context, args *LookupConnectionArgs, opts ...pulumi.InvokeOption) (*LookupConnectionResult, error) {
	var rv LookupConnectionResult
	err := ctx.Invoke("oci:DevOps/getConnection:getConnection", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getConnection.
type LookupConnectionArgs struct {
	// Unique connection identifier.
	ConnectionId string `pulumi:"connectionId"`
}

// A collection of values returned by getConnection.
type LookupConnectionResult struct {
	// The OCID of personal access token saved in secret store.
	AccessToken string `pulumi:"accessToken"`
	// OCID of personal Bitbucket Cloud AppPassword saved in secret store
	AppPassword string `pulumi:"appPassword"`
	// The Base URL of the hosted BitbucketServer.
	BaseUrl string `pulumi:"baseUrl"`
	// The OCID of the compartment containing the connection.
	CompartmentId string `pulumi:"compartmentId"`
	ConnectionId  string `pulumi:"connectionId"`
	// The type of connection.
	ConnectionType string `pulumi:"connectionType"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Optional description about the connection.
	Description string `pulumi:"description"`
	// Connection display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Unique identifier that is immutable on creation.
	Id string `pulumi:"id"`
	// The OCID of the DevOps project.
	ProjectId string `pulumi:"projectId"`
	// The current state of the connection.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time the connection was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated string `pulumi:"timeCreated"`
	// The time the connection was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated string `pulumi:"timeUpdated"`
	// TLS configuration used by build service to verify TLS connection.
	TlsVerifyConfigs []GetConnectionTlsVerifyConfig `pulumi:"tlsVerifyConfigs"`
	// Public Bitbucket Cloud Username in plain text
	Username string `pulumi:"username"`
}

func LookupConnectionOutput(ctx *pulumi.Context, args LookupConnectionOutputArgs, opts ...pulumi.InvokeOption) LookupConnectionResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupConnectionResult, error) {
			args := v.(LookupConnectionArgs)
			r, err := LookupConnection(ctx, &args, opts...)
			var s LookupConnectionResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupConnectionResultOutput)
}

// A collection of arguments for invoking getConnection.
type LookupConnectionOutputArgs struct {
	// Unique connection identifier.
	ConnectionId pulumi.StringInput `pulumi:"connectionId"`
}

func (LookupConnectionOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupConnectionArgs)(nil)).Elem()
}

// A collection of values returned by getConnection.
type LookupConnectionResultOutput struct{ *pulumi.OutputState }

func (LookupConnectionResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupConnectionResult)(nil)).Elem()
}

func (o LookupConnectionResultOutput) ToLookupConnectionResultOutput() LookupConnectionResultOutput {
	return o
}

func (o LookupConnectionResultOutput) ToLookupConnectionResultOutputWithContext(ctx context.Context) LookupConnectionResultOutput {
	return o
}

// The OCID of personal access token saved in secret store.
func (o LookupConnectionResultOutput) AccessToken() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.AccessToken }).(pulumi.StringOutput)
}

// OCID of personal Bitbucket Cloud AppPassword saved in secret store
func (o LookupConnectionResultOutput) AppPassword() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.AppPassword }).(pulumi.StringOutput)
}

// The Base URL of the hosted BitbucketServer.
func (o LookupConnectionResultOutput) BaseUrl() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.BaseUrl }).(pulumi.StringOutput)
}

// The OCID of the compartment containing the connection.
func (o LookupConnectionResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o LookupConnectionResultOutput) ConnectionId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.ConnectionId }).(pulumi.StringOutput)
}

// The type of connection.
func (o LookupConnectionResultOutput) ConnectionType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.ConnectionType }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupConnectionResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupConnectionResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Optional description about the connection.
func (o LookupConnectionResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.Description }).(pulumi.StringOutput)
}

// Connection display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
func (o LookupConnectionResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
func (o LookupConnectionResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupConnectionResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// Unique identifier that is immutable on creation.
func (o LookupConnectionResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the DevOps project.
func (o LookupConnectionResultOutput) ProjectId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.ProjectId }).(pulumi.StringOutput)
}

// The current state of the connection.
func (o LookupConnectionResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupConnectionResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupConnectionResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The time the connection was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o LookupConnectionResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the connection was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o LookupConnectionResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// TLS configuration used by build service to verify TLS connection.
func (o LookupConnectionResultOutput) TlsVerifyConfigs() GetConnectionTlsVerifyConfigArrayOutput {
	return o.ApplyT(func(v LookupConnectionResult) []GetConnectionTlsVerifyConfig { return v.TlsVerifyConfigs }).(GetConnectionTlsVerifyConfigArrayOutput)
}

// Public Bitbucket Cloud Username in plain text
func (o LookupConnectionResultOutput) Username() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionResult) string { return v.Username }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupConnectionResultOutput{})
}