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

// This resource provides the External Listener resource in Oracle Cloud Infrastructure Database Management service.
//
// Updates the external listener specified by `externalListenerId`.
//
// ## Import
//
// ExternalListeners can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DatabaseManagement/externalListener:ExternalListener test_external_listener "id"
// ```
type ExternalListener struct {
	pulumi.CustomResourceState

	// The additional details of the external listener defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails pulumi.StringMapOutput `pulumi:"additionalDetails"`
	// The directory that stores tracing and logging incidents when Automatic Diagnostic Repository (ADR) is enabled.
	AdrHomeDirectory pulumi.StringOutput `pulumi:"adrHomeDirectory"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The name of the external listener.
	ComponentName pulumi.StringOutput `pulumi:"componentName"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// The user-friendly name for the database. The name does not have to be unique.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The list of protocol addresses the listener is configured to listen on.
	Endpoints ExternalListenerEndpointArrayOutput `pulumi:"endpoints"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId pulumi.StringOutput `pulumi:"externalConnectorId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB home.
	ExternalDbHomeId pulumi.StringOutput `pulumi:"externalDbHomeId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
	ExternalDbNodeId pulumi.StringOutput `pulumi:"externalDbNodeId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the listener is a part of.
	ExternalDbSystemId pulumi.StringOutput `pulumi:"externalDbSystemId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
	ExternalListenerId pulumi.StringOutput `pulumi:"externalListenerId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The name of the host on which the external listener is running.
	HostName pulumi.StringOutput `pulumi:"hostName"`
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The listener alias.
	ListenerAlias pulumi.StringOutput `pulumi:"listenerAlias"`
	// The location of the listener configuration file listener.ora.
	ListenerOraLocation pulumi.StringOutput `pulumi:"listenerOraLocation"`
	// The type of listener.
	ListenerType pulumi.StringOutput `pulumi:"listenerType"`
	// The destination directory of the listener log file.
	LogDirectory pulumi.StringOutput `pulumi:"logDirectory"`
	// The Oracle home location of the listener.
	OracleHome pulumi.StringOutput `pulumi:"oracleHome"`
	// The list of ASMs that are serviced by the listener.
	ServicedAsms ExternalListenerServicedAsmArrayOutput `pulumi:"servicedAsms"`
	// The list of databases that are serviced by the listener.
	ServicedDatabases ExternalListenerServicedDatabaseArrayOutput `pulumi:"servicedDatabases"`
	// The current lifecycle state of the external listener.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The date and time the external listener was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the external listener was last updated.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The destination directory of the listener trace file.
	TraceDirectory pulumi.StringOutput `pulumi:"traceDirectory"`
	// The listener version.
	Version pulumi.StringOutput `pulumi:"version"`
}

// NewExternalListener registers a new resource with the given unique name, arguments, and options.
func NewExternalListener(ctx *pulumi.Context,
	name string, args *ExternalListenerArgs, opts ...pulumi.ResourceOption) (*ExternalListener, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ExternalListenerId == nil {
		return nil, errors.New("invalid value for required argument 'ExternalListenerId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ExternalListener
	err := ctx.RegisterResource("oci:DatabaseManagement/externalListener:ExternalListener", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetExternalListener gets an existing ExternalListener resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetExternalListener(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ExternalListenerState, opts ...pulumi.ResourceOption) (*ExternalListener, error) {
	var resource ExternalListener
	err := ctx.ReadResource("oci:DatabaseManagement/externalListener:ExternalListener", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ExternalListener resources.
type externalListenerState struct {
	// The additional details of the external listener defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails map[string]string `pulumi:"additionalDetails"`
	// The directory that stores tracing and logging incidents when Automatic Diagnostic Repository (ADR) is enabled.
	AdrHomeDirectory *string `pulumi:"adrHomeDirectory"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
	CompartmentId *string `pulumi:"compartmentId"`
	// The name of the external listener.
	ComponentName *string `pulumi:"componentName"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The user-friendly name for the database. The name does not have to be unique.
	DisplayName *string `pulumi:"displayName"`
	// The list of protocol addresses the listener is configured to listen on.
	Endpoints []ExternalListenerEndpoint `pulumi:"endpoints"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId *string `pulumi:"externalConnectorId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB home.
	ExternalDbHomeId *string `pulumi:"externalDbHomeId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
	ExternalDbNodeId *string `pulumi:"externalDbNodeId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the listener is a part of.
	ExternalDbSystemId *string `pulumi:"externalDbSystemId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
	ExternalListenerId *string `pulumi:"externalListenerId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The name of the host on which the external listener is running.
	HostName *string `pulumi:"hostName"`
	// Additional information about the current lifecycle state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The listener alias.
	ListenerAlias *string `pulumi:"listenerAlias"`
	// The location of the listener configuration file listener.ora.
	ListenerOraLocation *string `pulumi:"listenerOraLocation"`
	// The type of listener.
	ListenerType *string `pulumi:"listenerType"`
	// The destination directory of the listener log file.
	LogDirectory *string `pulumi:"logDirectory"`
	// The Oracle home location of the listener.
	OracleHome *string `pulumi:"oracleHome"`
	// The list of ASMs that are serviced by the listener.
	ServicedAsms []ExternalListenerServicedAsm `pulumi:"servicedAsms"`
	// The list of databases that are serviced by the listener.
	ServicedDatabases []ExternalListenerServicedDatabase `pulumi:"servicedDatabases"`
	// The current lifecycle state of the external listener.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the external listener was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the external listener was last updated.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The destination directory of the listener trace file.
	TraceDirectory *string `pulumi:"traceDirectory"`
	// The listener version.
	Version *string `pulumi:"version"`
}

type ExternalListenerState struct {
	// The additional details of the external listener defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails pulumi.StringMapInput
	// The directory that stores tracing and logging incidents when Automatic Diagnostic Repository (ADR) is enabled.
	AdrHomeDirectory pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
	CompartmentId pulumi.StringPtrInput
	// The name of the external listener.
	ComponentName pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// The user-friendly name for the database. The name does not have to be unique.
	DisplayName pulumi.StringPtrInput
	// The list of protocol addresses the listener is configured to listen on.
	Endpoints ExternalListenerEndpointArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB home.
	ExternalDbHomeId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
	ExternalDbNodeId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the listener is a part of.
	ExternalDbSystemId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
	ExternalListenerId pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// The name of the host on which the external listener is running.
	HostName pulumi.StringPtrInput
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringPtrInput
	// The listener alias.
	ListenerAlias pulumi.StringPtrInput
	// The location of the listener configuration file listener.ora.
	ListenerOraLocation pulumi.StringPtrInput
	// The type of listener.
	ListenerType pulumi.StringPtrInput
	// The destination directory of the listener log file.
	LogDirectory pulumi.StringPtrInput
	// The Oracle home location of the listener.
	OracleHome pulumi.StringPtrInput
	// The list of ASMs that are serviced by the listener.
	ServicedAsms ExternalListenerServicedAsmArrayInput
	// The list of databases that are serviced by the listener.
	ServicedDatabases ExternalListenerServicedDatabaseArrayInput
	// The current lifecycle state of the external listener.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The date and time the external listener was created.
	TimeCreated pulumi.StringPtrInput
	// The date and time the external listener was last updated.
	TimeUpdated pulumi.StringPtrInput
	// The destination directory of the listener trace file.
	TraceDirectory pulumi.StringPtrInput
	// The listener version.
	Version pulumi.StringPtrInput
}

func (ExternalListenerState) ElementType() reflect.Type {
	return reflect.TypeOf((*externalListenerState)(nil)).Elem()
}

type externalListenerArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId *string `pulumi:"externalConnectorId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
	ExternalListenerId string `pulumi:"externalListenerId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
}

// The set of arguments for constructing a ExternalListener resource.
type ExternalListenerArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
	ExternalListenerId pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
}

func (ExternalListenerArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*externalListenerArgs)(nil)).Elem()
}

type ExternalListenerInput interface {
	pulumi.Input

	ToExternalListenerOutput() ExternalListenerOutput
	ToExternalListenerOutputWithContext(ctx context.Context) ExternalListenerOutput
}

func (*ExternalListener) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalListener)(nil)).Elem()
}

func (i *ExternalListener) ToExternalListenerOutput() ExternalListenerOutput {
	return i.ToExternalListenerOutputWithContext(context.Background())
}

func (i *ExternalListener) ToExternalListenerOutputWithContext(ctx context.Context) ExternalListenerOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalListenerOutput)
}

// ExternalListenerArrayInput is an input type that accepts ExternalListenerArray and ExternalListenerArrayOutput values.
// You can construct a concrete instance of `ExternalListenerArrayInput` via:
//
//	ExternalListenerArray{ ExternalListenerArgs{...} }
type ExternalListenerArrayInput interface {
	pulumi.Input

	ToExternalListenerArrayOutput() ExternalListenerArrayOutput
	ToExternalListenerArrayOutputWithContext(context.Context) ExternalListenerArrayOutput
}

type ExternalListenerArray []ExternalListenerInput

func (ExternalListenerArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalListener)(nil)).Elem()
}

func (i ExternalListenerArray) ToExternalListenerArrayOutput() ExternalListenerArrayOutput {
	return i.ToExternalListenerArrayOutputWithContext(context.Background())
}

func (i ExternalListenerArray) ToExternalListenerArrayOutputWithContext(ctx context.Context) ExternalListenerArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalListenerArrayOutput)
}

// ExternalListenerMapInput is an input type that accepts ExternalListenerMap and ExternalListenerMapOutput values.
// You can construct a concrete instance of `ExternalListenerMapInput` via:
//
//	ExternalListenerMap{ "key": ExternalListenerArgs{...} }
type ExternalListenerMapInput interface {
	pulumi.Input

	ToExternalListenerMapOutput() ExternalListenerMapOutput
	ToExternalListenerMapOutputWithContext(context.Context) ExternalListenerMapOutput
}

type ExternalListenerMap map[string]ExternalListenerInput

func (ExternalListenerMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalListener)(nil)).Elem()
}

func (i ExternalListenerMap) ToExternalListenerMapOutput() ExternalListenerMapOutput {
	return i.ToExternalListenerMapOutputWithContext(context.Background())
}

func (i ExternalListenerMap) ToExternalListenerMapOutputWithContext(ctx context.Context) ExternalListenerMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalListenerMapOutput)
}

type ExternalListenerOutput struct{ *pulumi.OutputState }

func (ExternalListenerOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalListener)(nil)).Elem()
}

func (o ExternalListenerOutput) ToExternalListenerOutput() ExternalListenerOutput {
	return o
}

func (o ExternalListenerOutput) ToExternalListenerOutputWithContext(ctx context.Context) ExternalListenerOutput {
	return o
}

// The additional details of the external listener defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
func (o ExternalListenerOutput) AdditionalDetails() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringMapOutput { return v.AdditionalDetails }).(pulumi.StringMapOutput)
}

// The directory that stores tracing and logging incidents when Automatic Diagnostic Repository (ADR) is enabled.
func (o ExternalListenerOutput) AdrHomeDirectory() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.AdrHomeDirectory }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
func (o ExternalListenerOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// The name of the external listener.
func (o ExternalListenerOutput) ComponentName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.ComponentName }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o ExternalListenerOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The user-friendly name for the database. The name does not have to be unique.
func (o ExternalListenerOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The list of protocol addresses the listener is configured to listen on.
func (o ExternalListenerOutput) Endpoints() ExternalListenerEndpointArrayOutput {
	return o.ApplyT(func(v *ExternalListener) ExternalListenerEndpointArrayOutput { return v.Endpoints }).(ExternalListenerEndpointArrayOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
func (o ExternalListenerOutput) ExternalConnectorId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.ExternalConnectorId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB home.
func (o ExternalListenerOutput) ExternalDbHomeId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.ExternalDbHomeId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
func (o ExternalListenerOutput) ExternalDbNodeId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.ExternalDbNodeId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the listener is a part of.
func (o ExternalListenerOutput) ExternalDbSystemId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.ExternalDbSystemId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
func (o ExternalListenerOutput) ExternalListenerId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.ExternalListenerId }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ExternalListenerOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The name of the host on which the external listener is running.
func (o ExternalListenerOutput) HostName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.HostName }).(pulumi.StringOutput)
}

// Additional information about the current lifecycle state.
func (o ExternalListenerOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The listener alias.
func (o ExternalListenerOutput) ListenerAlias() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.ListenerAlias }).(pulumi.StringOutput)
}

// The location of the listener configuration file listener.ora.
func (o ExternalListenerOutput) ListenerOraLocation() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.ListenerOraLocation }).(pulumi.StringOutput)
}

// The type of listener.
func (o ExternalListenerOutput) ListenerType() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.ListenerType }).(pulumi.StringOutput)
}

// The destination directory of the listener log file.
func (o ExternalListenerOutput) LogDirectory() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.LogDirectory }).(pulumi.StringOutput)
}

// The Oracle home location of the listener.
func (o ExternalListenerOutput) OracleHome() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.OracleHome }).(pulumi.StringOutput)
}

// The list of ASMs that are serviced by the listener.
func (o ExternalListenerOutput) ServicedAsms() ExternalListenerServicedAsmArrayOutput {
	return o.ApplyT(func(v *ExternalListener) ExternalListenerServicedAsmArrayOutput { return v.ServicedAsms }).(ExternalListenerServicedAsmArrayOutput)
}

// The list of databases that are serviced by the listener.
func (o ExternalListenerOutput) ServicedDatabases() ExternalListenerServicedDatabaseArrayOutput {
	return o.ApplyT(func(v *ExternalListener) ExternalListenerServicedDatabaseArrayOutput { return v.ServicedDatabases }).(ExternalListenerServicedDatabaseArrayOutput)
}

// The current lifecycle state of the external listener.
func (o ExternalListenerOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o ExternalListenerOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the external listener was created.
func (o ExternalListenerOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the external listener was last updated.
func (o ExternalListenerOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The destination directory of the listener trace file.
func (o ExternalListenerOutput) TraceDirectory() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.TraceDirectory }).(pulumi.StringOutput)
}

// The listener version.
func (o ExternalListenerOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalListener) pulumi.StringOutput { return v.Version }).(pulumi.StringOutput)
}

type ExternalListenerArrayOutput struct{ *pulumi.OutputState }

func (ExternalListenerArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalListener)(nil)).Elem()
}

func (o ExternalListenerArrayOutput) ToExternalListenerArrayOutput() ExternalListenerArrayOutput {
	return o
}

func (o ExternalListenerArrayOutput) ToExternalListenerArrayOutputWithContext(ctx context.Context) ExternalListenerArrayOutput {
	return o
}

func (o ExternalListenerArrayOutput) Index(i pulumi.IntInput) ExternalListenerOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ExternalListener {
		return vs[0].([]*ExternalListener)[vs[1].(int)]
	}).(ExternalListenerOutput)
}

type ExternalListenerMapOutput struct{ *pulumi.OutputState }

func (ExternalListenerMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalListener)(nil)).Elem()
}

func (o ExternalListenerMapOutput) ToExternalListenerMapOutput() ExternalListenerMapOutput {
	return o
}

func (o ExternalListenerMapOutput) ToExternalListenerMapOutputWithContext(ctx context.Context) ExternalListenerMapOutput {
	return o
}

func (o ExternalListenerMapOutput) MapIndex(k pulumi.StringInput) ExternalListenerOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ExternalListener {
		return vs[0].(map[string]*ExternalListener)[vs[1].(string)]
	}).(ExternalListenerOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalListenerInput)(nil)).Elem(), &ExternalListener{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalListenerArrayInput)(nil)).Elem(), ExternalListenerArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalListenerMapInput)(nil)).Elem(), ExternalListenerMap{})
	pulumi.RegisterOutputType(ExternalListenerOutput{})
	pulumi.RegisterOutputType(ExternalListenerArrayOutput{})
	pulumi.RegisterOutputType(ExternalListenerMapOutput{})
}
