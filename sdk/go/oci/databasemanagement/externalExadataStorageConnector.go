// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the External Exadata Storage Connector resource in Oracle Cloud Infrastructure Database Management service.
//
// Creates the Exadata storage server connector after validating the connection information.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/databasemanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := databasemanagement.NewExternalExadataStorageConnector(ctx, "test_external_exadata_storage_connector", &databasemanagement.ExternalExadataStorageConnectorArgs{
//				AgentId:       pulumi.Any(testAgent.Id),
//				ConnectionUri: pulumi.Any(externalExadataStorageConnectorConnectionUri),
//				ConnectorName: pulumi.Any(externalExadataStorageConnectorConnectorName),
//				CredentialInfo: &databasemanagement.ExternalExadataStorageConnectorCredentialInfoArgs{
//					Password:              pulumi.Any(externalExadataStorageConnectorCredentialInfoPassword),
//					Username:              pulumi.Any(externalExadataStorageConnectorCredentialInfoUsername),
//					SslTrustStoreLocation: pulumi.Any(externalExadataStorageConnectorCredentialInfoSslTrustStoreLocation),
//					SslTrustStorePassword: pulumi.Any(externalExadataStorageConnectorCredentialInfoSslTrustStorePassword),
//					SslTrustStoreType:     pulumi.Any(externalExadataStorageConnectorCredentialInfoSslTrustStoreType),
//				},
//				StorageServerId: pulumi.Any(testStorageServer.Id),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
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
// ExternalExadataStorageConnectors can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DatabaseManagement/externalExadataStorageConnector:ExternalExadataStorageConnector test_external_exadata_storage_connector "id"
// ```
type ExternalExadataStorageConnector struct {
	pulumi.CustomResourceState

	// The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails pulumi.StringMapOutput `pulumi:"additionalDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent for the Exadata storage server.
	AgentId pulumi.StringOutput `pulumi:"agentId"`
	// (Updatable) The unique string of the connection. For example, "https://<storage-server-name>/MS/RESTService/".
	ConnectionUri pulumi.StringOutput `pulumi:"connectionUri"`
	// (Updatable) The name of the Exadata storage server connector.
	ConnectorName pulumi.StringOutput `pulumi:"connectorName"`
	// (Updatable) The user credential information.
	CredentialInfo ExternalExadataStorageConnectorCredentialInfoOutput `pulumi:"credentialInfo"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// The name of the Exadata resource. English letters, numbers, "-", "_" and "." only.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
	ExadataInfrastructureId pulumi.StringOutput `pulumi:"exadataInfrastructureId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The internal ID of the Exadata resource.
	InternalId pulumi.StringOutput `pulumi:"internalId"`
	// The details of the lifecycle state of the Exadata resource.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The current lifecycle state of the database resource.
	State pulumi.StringOutput `pulumi:"state"`
	// The status of the Exadata resource.
	Status pulumi.StringOutput `pulumi:"status"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageServerId pulumi.StringOutput `pulumi:"storageServerId"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The timestamp of the creation of the Exadata resource.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The timestamp of the last update of the Exadata resource.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The version of the Exadata resource.
	Version pulumi.StringOutput `pulumi:"version"`
}

// NewExternalExadataStorageConnector registers a new resource with the given unique name, arguments, and options.
func NewExternalExadataStorageConnector(ctx *pulumi.Context,
	name string, args *ExternalExadataStorageConnectorArgs, opts ...pulumi.ResourceOption) (*ExternalExadataStorageConnector, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AgentId == nil {
		return nil, errors.New("invalid value for required argument 'AgentId'")
	}
	if args.ConnectionUri == nil {
		return nil, errors.New("invalid value for required argument 'ConnectionUri'")
	}
	if args.ConnectorName == nil {
		return nil, errors.New("invalid value for required argument 'ConnectorName'")
	}
	if args.CredentialInfo == nil {
		return nil, errors.New("invalid value for required argument 'CredentialInfo'")
	}
	if args.StorageServerId == nil {
		return nil, errors.New("invalid value for required argument 'StorageServerId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ExternalExadataStorageConnector
	err := ctx.RegisterResource("oci:DatabaseManagement/externalExadataStorageConnector:ExternalExadataStorageConnector", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetExternalExadataStorageConnector gets an existing ExternalExadataStorageConnector resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetExternalExadataStorageConnector(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ExternalExadataStorageConnectorState, opts ...pulumi.ResourceOption) (*ExternalExadataStorageConnector, error) {
	var resource ExternalExadataStorageConnector
	err := ctx.ReadResource("oci:DatabaseManagement/externalExadataStorageConnector:ExternalExadataStorageConnector", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ExternalExadataStorageConnector resources.
type externalExadataStorageConnectorState struct {
	// The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails map[string]string `pulumi:"additionalDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent for the Exadata storage server.
	AgentId *string `pulumi:"agentId"`
	// (Updatable) The unique string of the connection. For example, "https://<storage-server-name>/MS/RESTService/".
	ConnectionUri *string `pulumi:"connectionUri"`
	// (Updatable) The name of the Exadata storage server connector.
	ConnectorName *string `pulumi:"connectorName"`
	// (Updatable) The user credential information.
	CredentialInfo *ExternalExadataStorageConnectorCredentialInfo `pulumi:"credentialInfo"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The name of the Exadata resource. English letters, numbers, "-", "_" and "." only.
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
	ExadataInfrastructureId *string `pulumi:"exadataInfrastructureId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The internal ID of the Exadata resource.
	InternalId *string `pulumi:"internalId"`
	// The details of the lifecycle state of the Exadata resource.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The current lifecycle state of the database resource.
	State *string `pulumi:"state"`
	// The status of the Exadata resource.
	Status *string `pulumi:"status"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageServerId *string `pulumi:"storageServerId"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The timestamp of the creation of the Exadata resource.
	TimeCreated *string `pulumi:"timeCreated"`
	// The timestamp of the last update of the Exadata resource.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The version of the Exadata resource.
	Version *string `pulumi:"version"`
}

type ExternalExadataStorageConnectorState struct {
	// The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails pulumi.StringMapInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent for the Exadata storage server.
	AgentId pulumi.StringPtrInput
	// (Updatable) The unique string of the connection. For example, "https://<storage-server-name>/MS/RESTService/".
	ConnectionUri pulumi.StringPtrInput
	// (Updatable) The name of the Exadata storage server connector.
	ConnectorName pulumi.StringPtrInput
	// (Updatable) The user credential information.
	CredentialInfo ExternalExadataStorageConnectorCredentialInfoPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// The name of the Exadata resource. English letters, numbers, "-", "_" and "." only.
	DisplayName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
	ExadataInfrastructureId pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// The internal ID of the Exadata resource.
	InternalId pulumi.StringPtrInput
	// The details of the lifecycle state of the Exadata resource.
	LifecycleDetails pulumi.StringPtrInput
	// The current lifecycle state of the database resource.
	State pulumi.StringPtrInput
	// The status of the Exadata resource.
	Status pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageServerId pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The timestamp of the creation of the Exadata resource.
	TimeCreated pulumi.StringPtrInput
	// The timestamp of the last update of the Exadata resource.
	TimeUpdated pulumi.StringPtrInput
	// The version of the Exadata resource.
	Version pulumi.StringPtrInput
}

func (ExternalExadataStorageConnectorState) ElementType() reflect.Type {
	return reflect.TypeOf((*externalExadataStorageConnectorState)(nil)).Elem()
}

type externalExadataStorageConnectorArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent for the Exadata storage server.
	AgentId string `pulumi:"agentId"`
	// (Updatable) The unique string of the connection. For example, "https://<storage-server-name>/MS/RESTService/".
	ConnectionUri string `pulumi:"connectionUri"`
	// (Updatable) The name of the Exadata storage server connector.
	ConnectorName string `pulumi:"connectorName"`
	// (Updatable) The user credential information.
	CredentialInfo ExternalExadataStorageConnectorCredentialInfo `pulumi:"credentialInfo"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageServerId string `pulumi:"storageServerId"`
}

// The set of arguments for constructing a ExternalExadataStorageConnector resource.
type ExternalExadataStorageConnectorArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent for the Exadata storage server.
	AgentId pulumi.StringInput
	// (Updatable) The unique string of the connection. For example, "https://<storage-server-name>/MS/RESTService/".
	ConnectionUri pulumi.StringInput
	// (Updatable) The name of the Exadata storage server connector.
	ConnectorName pulumi.StringInput
	// (Updatable) The user credential information.
	CredentialInfo ExternalExadataStorageConnectorCredentialInfoInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageServerId pulumi.StringInput
}

func (ExternalExadataStorageConnectorArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*externalExadataStorageConnectorArgs)(nil)).Elem()
}

type ExternalExadataStorageConnectorInput interface {
	pulumi.Input

	ToExternalExadataStorageConnectorOutput() ExternalExadataStorageConnectorOutput
	ToExternalExadataStorageConnectorOutputWithContext(ctx context.Context) ExternalExadataStorageConnectorOutput
}

func (*ExternalExadataStorageConnector) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalExadataStorageConnector)(nil)).Elem()
}

func (i *ExternalExadataStorageConnector) ToExternalExadataStorageConnectorOutput() ExternalExadataStorageConnectorOutput {
	return i.ToExternalExadataStorageConnectorOutputWithContext(context.Background())
}

func (i *ExternalExadataStorageConnector) ToExternalExadataStorageConnectorOutputWithContext(ctx context.Context) ExternalExadataStorageConnectorOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalExadataStorageConnectorOutput)
}

// ExternalExadataStorageConnectorArrayInput is an input type that accepts ExternalExadataStorageConnectorArray and ExternalExadataStorageConnectorArrayOutput values.
// You can construct a concrete instance of `ExternalExadataStorageConnectorArrayInput` via:
//
//	ExternalExadataStorageConnectorArray{ ExternalExadataStorageConnectorArgs{...} }
type ExternalExadataStorageConnectorArrayInput interface {
	pulumi.Input

	ToExternalExadataStorageConnectorArrayOutput() ExternalExadataStorageConnectorArrayOutput
	ToExternalExadataStorageConnectorArrayOutputWithContext(context.Context) ExternalExadataStorageConnectorArrayOutput
}

type ExternalExadataStorageConnectorArray []ExternalExadataStorageConnectorInput

func (ExternalExadataStorageConnectorArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalExadataStorageConnector)(nil)).Elem()
}

func (i ExternalExadataStorageConnectorArray) ToExternalExadataStorageConnectorArrayOutput() ExternalExadataStorageConnectorArrayOutput {
	return i.ToExternalExadataStorageConnectorArrayOutputWithContext(context.Background())
}

func (i ExternalExadataStorageConnectorArray) ToExternalExadataStorageConnectorArrayOutputWithContext(ctx context.Context) ExternalExadataStorageConnectorArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalExadataStorageConnectorArrayOutput)
}

// ExternalExadataStorageConnectorMapInput is an input type that accepts ExternalExadataStorageConnectorMap and ExternalExadataStorageConnectorMapOutput values.
// You can construct a concrete instance of `ExternalExadataStorageConnectorMapInput` via:
//
//	ExternalExadataStorageConnectorMap{ "key": ExternalExadataStorageConnectorArgs{...} }
type ExternalExadataStorageConnectorMapInput interface {
	pulumi.Input

	ToExternalExadataStorageConnectorMapOutput() ExternalExadataStorageConnectorMapOutput
	ToExternalExadataStorageConnectorMapOutputWithContext(context.Context) ExternalExadataStorageConnectorMapOutput
}

type ExternalExadataStorageConnectorMap map[string]ExternalExadataStorageConnectorInput

func (ExternalExadataStorageConnectorMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalExadataStorageConnector)(nil)).Elem()
}

func (i ExternalExadataStorageConnectorMap) ToExternalExadataStorageConnectorMapOutput() ExternalExadataStorageConnectorMapOutput {
	return i.ToExternalExadataStorageConnectorMapOutputWithContext(context.Background())
}

func (i ExternalExadataStorageConnectorMap) ToExternalExadataStorageConnectorMapOutputWithContext(ctx context.Context) ExternalExadataStorageConnectorMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalExadataStorageConnectorMapOutput)
}

type ExternalExadataStorageConnectorOutput struct{ *pulumi.OutputState }

func (ExternalExadataStorageConnectorOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalExadataStorageConnector)(nil)).Elem()
}

func (o ExternalExadataStorageConnectorOutput) ToExternalExadataStorageConnectorOutput() ExternalExadataStorageConnectorOutput {
	return o
}

func (o ExternalExadataStorageConnectorOutput) ToExternalExadataStorageConnectorOutputWithContext(ctx context.Context) ExternalExadataStorageConnectorOutput {
	return o
}

// The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
func (o ExternalExadataStorageConnectorOutput) AdditionalDetails() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringMapOutput { return v.AdditionalDetails }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent for the Exadata storage server.
func (o ExternalExadataStorageConnectorOutput) AgentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.AgentId }).(pulumi.StringOutput)
}

// (Updatable) The unique string of the connection. For example, "https://<storage-server-name>/MS/RESTService/".
func (o ExternalExadataStorageConnectorOutput) ConnectionUri() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.ConnectionUri }).(pulumi.StringOutput)
}

// (Updatable) The name of the Exadata storage server connector.
func (o ExternalExadataStorageConnectorOutput) ConnectorName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.ConnectorName }).(pulumi.StringOutput)
}

// (Updatable) The user credential information.
func (o ExternalExadataStorageConnectorOutput) CredentialInfo() ExternalExadataStorageConnectorCredentialInfoOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) ExternalExadataStorageConnectorCredentialInfoOutput {
		return v.CredentialInfo
	}).(ExternalExadataStorageConnectorCredentialInfoOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o ExternalExadataStorageConnectorOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The name of the Exadata resource. English letters, numbers, "-", "_" and "." only.
func (o ExternalExadataStorageConnectorOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
func (o ExternalExadataStorageConnectorOutput) ExadataInfrastructureId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.ExadataInfrastructureId }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o ExternalExadataStorageConnectorOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The internal ID of the Exadata resource.
func (o ExternalExadataStorageConnectorOutput) InternalId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.InternalId }).(pulumi.StringOutput)
}

// The details of the lifecycle state of the Exadata resource.
func (o ExternalExadataStorageConnectorOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The current lifecycle state of the database resource.
func (o ExternalExadataStorageConnectorOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The status of the Exadata resource.
func (o ExternalExadataStorageConnectorOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.Status }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ExternalExadataStorageConnectorOutput) StorageServerId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.StorageServerId }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o ExternalExadataStorageConnectorOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The timestamp of the creation of the Exadata resource.
func (o ExternalExadataStorageConnectorOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The timestamp of the last update of the Exadata resource.
func (o ExternalExadataStorageConnectorOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The version of the Exadata resource.
func (o ExternalExadataStorageConnectorOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataStorageConnector) pulumi.StringOutput { return v.Version }).(pulumi.StringOutput)
}

type ExternalExadataStorageConnectorArrayOutput struct{ *pulumi.OutputState }

func (ExternalExadataStorageConnectorArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalExadataStorageConnector)(nil)).Elem()
}

func (o ExternalExadataStorageConnectorArrayOutput) ToExternalExadataStorageConnectorArrayOutput() ExternalExadataStorageConnectorArrayOutput {
	return o
}

func (o ExternalExadataStorageConnectorArrayOutput) ToExternalExadataStorageConnectorArrayOutputWithContext(ctx context.Context) ExternalExadataStorageConnectorArrayOutput {
	return o
}

func (o ExternalExadataStorageConnectorArrayOutput) Index(i pulumi.IntInput) ExternalExadataStorageConnectorOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ExternalExadataStorageConnector {
		return vs[0].([]*ExternalExadataStorageConnector)[vs[1].(int)]
	}).(ExternalExadataStorageConnectorOutput)
}

type ExternalExadataStorageConnectorMapOutput struct{ *pulumi.OutputState }

func (ExternalExadataStorageConnectorMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalExadataStorageConnector)(nil)).Elem()
}

func (o ExternalExadataStorageConnectorMapOutput) ToExternalExadataStorageConnectorMapOutput() ExternalExadataStorageConnectorMapOutput {
	return o
}

func (o ExternalExadataStorageConnectorMapOutput) ToExternalExadataStorageConnectorMapOutputWithContext(ctx context.Context) ExternalExadataStorageConnectorMapOutput {
	return o
}

func (o ExternalExadataStorageConnectorMapOutput) MapIndex(k pulumi.StringInput) ExternalExadataStorageConnectorOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ExternalExadataStorageConnector {
		return vs[0].(map[string]*ExternalExadataStorageConnector)[vs[1].(string)]
	}).(ExternalExadataStorageConnectorOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalExadataStorageConnectorInput)(nil)).Elem(), &ExternalExadataStorageConnector{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalExadataStorageConnectorArrayInput)(nil)).Elem(), ExternalExadataStorageConnectorArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalExadataStorageConnectorMapInput)(nil)).Elem(), ExternalExadataStorageConnectorMap{})
	pulumi.RegisterOutputType(ExternalExadataStorageConnectorOutput{})
	pulumi.RegisterOutputType(ExternalExadataStorageConnectorArrayOutput{})
	pulumi.RegisterOutputType(ExternalExadataStorageConnectorMapOutput{})
}
