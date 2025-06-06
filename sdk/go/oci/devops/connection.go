// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Connection resource in Oracle Cloud Infrastructure Devops service.
//
// Creates a new connection.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/devops"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := devops.NewConnection(ctx, "test_connection", &devops.ConnectionArgs{
//				ConnectionType: pulumi.Any(connectionConnectionType),
//				ProjectId:      pulumi.Any(testProject.Id),
//				AccessToken:    pulumi.Any(connectionAccessToken),
//				AppPassword:    pulumi.Any(connectionAppPassword),
//				BaseUrl:        pulumi.Any(connectionBaseUrl),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				Description: pulumi.Any(connectionDescription),
//				DisplayName: pulumi.Any(connectionDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				TlsVerifyConfig: &devops.ConnectionTlsVerifyConfigArgs{
//					CaCertificateBundleId: pulumi.Any(testCaCertificateBundle.Id),
//					TlsVerifyMode:         pulumi.Any(connectionTlsVerifyConfigTlsVerifyMode),
//				},
//				Username: pulumi.Any(connectionUsername),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// Connections can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DevOps/connection:Connection test_connection "id"
// ```
type Connection struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of personal access token saved in secret store.
	AccessToken pulumi.StringOutput `pulumi:"accessToken"`
	// (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
	AppPassword pulumi.StringOutput `pulumi:"appPassword"`
	// (Updatable) The Base URL of the hosted BitbucketServer.
	BaseUrl pulumi.StringOutput `pulumi:"baseUrl"`
	// The OCID of the compartment containing the connection.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The type of connection.
	ConnectionType pulumi.StringOutput `pulumi:"connectionType"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Optional description about the connection.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Optional connection display name. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The result of validating the credentials of a connection.
	LastConnectionValidationResults ConnectionLastConnectionValidationResultArrayOutput `pulumi:"lastConnectionValidationResults"`
	// The OCID of the DevOps project.
	ProjectId pulumi.StringOutput `pulumi:"projectId"`
	// The current state of the connection.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time the connection was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the connection was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// (Updatable) TLS configuration used by build service to verify TLS connection.
	TlsVerifyConfig ConnectionTlsVerifyConfigOutput `pulumi:"tlsVerifyConfig"`
	// (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Username pulumi.StringOutput `pulumi:"username"`
}

// NewConnection registers a new resource with the given unique name, arguments, and options.
func NewConnection(ctx *pulumi.Context,
	name string, args *ConnectionArgs, opts ...pulumi.ResourceOption) (*Connection, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ConnectionType == nil {
		return nil, errors.New("invalid value for required argument 'ConnectionType'")
	}
	if args.ProjectId == nil {
		return nil, errors.New("invalid value for required argument 'ProjectId'")
	}
	if args.AppPassword != nil {
		args.AppPassword = pulumi.ToSecret(args.AppPassword).(pulumi.StringPtrInput)
	}
	secrets := pulumi.AdditionalSecretOutputs([]string{
		"appPassword",
	})
	opts = append(opts, secrets)
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Connection
	err := ctx.RegisterResource("oci:DevOps/connection:Connection", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetConnection gets an existing Connection resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetConnection(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ConnectionState, opts ...pulumi.ResourceOption) (*Connection, error) {
	var resource Connection
	err := ctx.ReadResource("oci:DevOps/connection:Connection", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Connection resources.
type connectionState struct {
	// (Updatable) The OCID of personal access token saved in secret store.
	AccessToken *string `pulumi:"accessToken"`
	// (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
	AppPassword *string `pulumi:"appPassword"`
	// (Updatable) The Base URL of the hosted BitbucketServer.
	BaseUrl *string `pulumi:"baseUrl"`
	// The OCID of the compartment containing the connection.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The type of connection.
	ConnectionType *string `pulumi:"connectionType"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Optional description about the connection.
	Description *string `pulumi:"description"`
	// (Updatable) Optional connection display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The result of validating the credentials of a connection.
	LastConnectionValidationResults []ConnectionLastConnectionValidationResult `pulumi:"lastConnectionValidationResults"`
	// The OCID of the DevOps project.
	ProjectId *string `pulumi:"projectId"`
	// The current state of the connection.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time the connection was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the connection was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
	// (Updatable) TLS configuration used by build service to verify TLS connection.
	TlsVerifyConfig *ConnectionTlsVerifyConfig `pulumi:"tlsVerifyConfig"`
	// (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Username *string `pulumi:"username"`
}

type ConnectionState struct {
	// (Updatable) The OCID of personal access token saved in secret store.
	AccessToken pulumi.StringPtrInput
	// (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
	AppPassword pulumi.StringPtrInput
	// (Updatable) The Base URL of the hosted BitbucketServer.
	BaseUrl pulumi.StringPtrInput
	// The OCID of the compartment containing the connection.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The type of connection.
	ConnectionType pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Optional description about the connection.
	Description pulumi.StringPtrInput
	// (Updatable) Optional connection display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// The result of validating the credentials of a connection.
	LastConnectionValidationResults ConnectionLastConnectionValidationResultArrayInput
	// The OCID of the DevOps project.
	ProjectId pulumi.StringPtrInput
	// The current state of the connection.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time the connection was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The time the connection was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
	// (Updatable) TLS configuration used by build service to verify TLS connection.
	TlsVerifyConfig ConnectionTlsVerifyConfigPtrInput
	// (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Username pulumi.StringPtrInput
}

func (ConnectionState) ElementType() reflect.Type {
	return reflect.TypeOf((*connectionState)(nil)).Elem()
}

type connectionArgs struct {
	// (Updatable) The OCID of personal access token saved in secret store.
	AccessToken *string `pulumi:"accessToken"`
	// (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
	AppPassword *string `pulumi:"appPassword"`
	// (Updatable) The Base URL of the hosted BitbucketServer.
	BaseUrl *string `pulumi:"baseUrl"`
	// (Updatable) The type of connection.
	ConnectionType string `pulumi:"connectionType"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Optional description about the connection.
	Description *string `pulumi:"description"`
	// (Updatable) Optional connection display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the DevOps project.
	ProjectId string `pulumi:"projectId"`
	// (Updatable) TLS configuration used by build service to verify TLS connection.
	TlsVerifyConfig *ConnectionTlsVerifyConfig `pulumi:"tlsVerifyConfig"`
	// (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Username *string `pulumi:"username"`
}

// The set of arguments for constructing a Connection resource.
type ConnectionArgs struct {
	// (Updatable) The OCID of personal access token saved in secret store.
	AccessToken pulumi.StringPtrInput
	// (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
	AppPassword pulumi.StringPtrInput
	// (Updatable) The Base URL of the hosted BitbucketServer.
	BaseUrl pulumi.StringPtrInput
	// (Updatable) The type of connection.
	ConnectionType pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Optional description about the connection.
	Description pulumi.StringPtrInput
	// (Updatable) Optional connection display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// The OCID of the DevOps project.
	ProjectId pulumi.StringInput
	// (Updatable) TLS configuration used by build service to verify TLS connection.
	TlsVerifyConfig ConnectionTlsVerifyConfigPtrInput
	// (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Username pulumi.StringPtrInput
}

func (ConnectionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*connectionArgs)(nil)).Elem()
}

type ConnectionInput interface {
	pulumi.Input

	ToConnectionOutput() ConnectionOutput
	ToConnectionOutputWithContext(ctx context.Context) ConnectionOutput
}

func (*Connection) ElementType() reflect.Type {
	return reflect.TypeOf((**Connection)(nil)).Elem()
}

func (i *Connection) ToConnectionOutput() ConnectionOutput {
	return i.ToConnectionOutputWithContext(context.Background())
}

func (i *Connection) ToConnectionOutputWithContext(ctx context.Context) ConnectionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ConnectionOutput)
}

// ConnectionArrayInput is an input type that accepts ConnectionArray and ConnectionArrayOutput values.
// You can construct a concrete instance of `ConnectionArrayInput` via:
//
//	ConnectionArray{ ConnectionArgs{...} }
type ConnectionArrayInput interface {
	pulumi.Input

	ToConnectionArrayOutput() ConnectionArrayOutput
	ToConnectionArrayOutputWithContext(context.Context) ConnectionArrayOutput
}

type ConnectionArray []ConnectionInput

func (ConnectionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Connection)(nil)).Elem()
}

func (i ConnectionArray) ToConnectionArrayOutput() ConnectionArrayOutput {
	return i.ToConnectionArrayOutputWithContext(context.Background())
}

func (i ConnectionArray) ToConnectionArrayOutputWithContext(ctx context.Context) ConnectionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ConnectionArrayOutput)
}

// ConnectionMapInput is an input type that accepts ConnectionMap and ConnectionMapOutput values.
// You can construct a concrete instance of `ConnectionMapInput` via:
//
//	ConnectionMap{ "key": ConnectionArgs{...} }
type ConnectionMapInput interface {
	pulumi.Input

	ToConnectionMapOutput() ConnectionMapOutput
	ToConnectionMapOutputWithContext(context.Context) ConnectionMapOutput
}

type ConnectionMap map[string]ConnectionInput

func (ConnectionMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Connection)(nil)).Elem()
}

func (i ConnectionMap) ToConnectionMapOutput() ConnectionMapOutput {
	return i.ToConnectionMapOutputWithContext(context.Background())
}

func (i ConnectionMap) ToConnectionMapOutputWithContext(ctx context.Context) ConnectionMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ConnectionMapOutput)
}

type ConnectionOutput struct{ *pulumi.OutputState }

func (ConnectionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Connection)(nil)).Elem()
}

func (o ConnectionOutput) ToConnectionOutput() ConnectionOutput {
	return o
}

func (o ConnectionOutput) ToConnectionOutputWithContext(ctx context.Context) ConnectionOutput {
	return o
}

// (Updatable) The OCID of personal access token saved in secret store.
func (o ConnectionOutput) AccessToken() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.AccessToken }).(pulumi.StringOutput)
}

// (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
func (o ConnectionOutput) AppPassword() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.AppPassword }).(pulumi.StringOutput)
}

// (Updatable) The Base URL of the hosted BitbucketServer.
func (o ConnectionOutput) BaseUrl() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.BaseUrl }).(pulumi.StringOutput)
}

// The OCID of the compartment containing the connection.
func (o ConnectionOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) The type of connection.
func (o ConnectionOutput) ConnectionType() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.ConnectionType }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
func (o ConnectionOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Optional description about the connection.
func (o ConnectionOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Optional connection display name. Avoid entering confidential information.
func (o ConnectionOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
func (o ConnectionOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The result of validating the credentials of a connection.
func (o ConnectionOutput) LastConnectionValidationResults() ConnectionLastConnectionValidationResultArrayOutput {
	return o.ApplyT(func(v *Connection) ConnectionLastConnectionValidationResultArrayOutput {
		return v.LastConnectionValidationResults
	}).(ConnectionLastConnectionValidationResultArrayOutput)
}

// The OCID of the DevOps project.
func (o ConnectionOutput) ProjectId() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.ProjectId }).(pulumi.StringOutput)
}

// The current state of the connection.
func (o ConnectionOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o ConnectionOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time the connection was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o ConnectionOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the connection was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o ConnectionOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// (Updatable) TLS configuration used by build service to verify TLS connection.
func (o ConnectionOutput) TlsVerifyConfig() ConnectionTlsVerifyConfigOutput {
	return o.ApplyT(func(v *Connection) ConnectionTlsVerifyConfigOutput { return v.TlsVerifyConfig }).(ConnectionTlsVerifyConfigOutput)
}

// (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ConnectionOutput) Username() pulumi.StringOutput {
	return o.ApplyT(func(v *Connection) pulumi.StringOutput { return v.Username }).(pulumi.StringOutput)
}

type ConnectionArrayOutput struct{ *pulumi.OutputState }

func (ConnectionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Connection)(nil)).Elem()
}

func (o ConnectionArrayOutput) ToConnectionArrayOutput() ConnectionArrayOutput {
	return o
}

func (o ConnectionArrayOutput) ToConnectionArrayOutputWithContext(ctx context.Context) ConnectionArrayOutput {
	return o
}

func (o ConnectionArrayOutput) Index(i pulumi.IntInput) ConnectionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Connection {
		return vs[0].([]*Connection)[vs[1].(int)]
	}).(ConnectionOutput)
}

type ConnectionMapOutput struct{ *pulumi.OutputState }

func (ConnectionMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Connection)(nil)).Elem()
}

func (o ConnectionMapOutput) ToConnectionMapOutput() ConnectionMapOutput {
	return o
}

func (o ConnectionMapOutput) ToConnectionMapOutputWithContext(ctx context.Context) ConnectionMapOutput {
	return o
}

func (o ConnectionMapOutput) MapIndex(k pulumi.StringInput) ConnectionOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Connection {
		return vs[0].(map[string]*Connection)[vs[1].(string)]
	}).(ConnectionOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ConnectionInput)(nil)).Elem(), &Connection{})
	pulumi.RegisterInputType(reflect.TypeOf((*ConnectionArrayInput)(nil)).Elem(), ConnectionArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ConnectionMapInput)(nil)).Elem(), ConnectionMap{})
	pulumi.RegisterOutputType(ConnectionOutput{})
	pulumi.RegisterOutputType(ConnectionArrayOutput{})
	pulumi.RegisterOutputType(ConnectionMapOutput{})
}
