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

// This resource provides the External Cluster resource in Oracle Cloud Infrastructure Database Management service.
//
// Updates the external cluster specified by `externalClusterId`.
//
// ## Import
//
// ExternalClusters can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DatabaseManagement/externalCluster:ExternalCluster test_external_cluster "id"
// ```
type ExternalCluster struct {
	pulumi.CustomResourceState

	// The additional details of the external cluster defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails pulumi.StringMapOutput `pulumi:"additionalDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The name of the external cluster.
	ComponentName pulumi.StringOutput `pulumi:"componentName"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// The user-friendly name for the external cluster. The name does not have to be unique.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
	ExternalClusterId pulumi.StringOutput `pulumi:"externalClusterId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId pulumi.StringOutput `pulumi:"externalConnectorId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster is a part of.
	ExternalDbSystemId pulumi.StringOutput `pulumi:"externalDbSystemId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The directory in which Oracle Grid Infrastructure is installed.
	GridHome pulumi.StringOutput `pulumi:"gridHome"`
	// Indicates whether the cluster is Oracle Flex Cluster or not.
	IsFlexCluster pulumi.BoolOutput `pulumi:"isFlexCluster"`
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The list of network address configurations of the external cluster.
	NetworkConfigurations ExternalClusterNetworkConfigurationArrayOutput `pulumi:"networkConfigurations"`
	// The location of the Oracle Cluster Registry (OCR).
	OcrFileLocation pulumi.StringOutput `pulumi:"ocrFileLocation"`
	// The list of Single Client Access Name (SCAN) configurations of the external cluster.
	ScanConfigurations ExternalClusterScanConfigurationArrayOutput `pulumi:"scanConfigurations"`
	// The current lifecycle state of the external cluster.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The date and time the external cluster was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the external cluster was last updated.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The cluster version.
	Version pulumi.StringOutput `pulumi:"version"`
	// The list of Virtual IP (VIP) configurations of the external cluster.
	VipConfigurations ExternalClusterVipConfigurationArrayOutput `pulumi:"vipConfigurations"`
}

// NewExternalCluster registers a new resource with the given unique name, arguments, and options.
func NewExternalCluster(ctx *pulumi.Context,
	name string, args *ExternalClusterArgs, opts ...pulumi.ResourceOption) (*ExternalCluster, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ExternalClusterId == nil {
		return nil, errors.New("invalid value for required argument 'ExternalClusterId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ExternalCluster
	err := ctx.RegisterResource("oci:DatabaseManagement/externalCluster:ExternalCluster", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetExternalCluster gets an existing ExternalCluster resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetExternalCluster(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ExternalClusterState, opts ...pulumi.ResourceOption) (*ExternalCluster, error) {
	var resource ExternalCluster
	err := ctx.ReadResource("oci:DatabaseManagement/externalCluster:ExternalCluster", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ExternalCluster resources.
type externalClusterState struct {
	// The additional details of the external cluster defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails map[string]string `pulumi:"additionalDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The name of the external cluster.
	ComponentName *string `pulumi:"componentName"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The user-friendly name for the external cluster. The name does not have to be unique.
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
	ExternalClusterId *string `pulumi:"externalClusterId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId *string `pulumi:"externalConnectorId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster is a part of.
	ExternalDbSystemId *string `pulumi:"externalDbSystemId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The directory in which Oracle Grid Infrastructure is installed.
	GridHome *string `pulumi:"gridHome"`
	// Indicates whether the cluster is Oracle Flex Cluster or not.
	IsFlexCluster *bool `pulumi:"isFlexCluster"`
	// Additional information about the current lifecycle state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The list of network address configurations of the external cluster.
	NetworkConfigurations []ExternalClusterNetworkConfiguration `pulumi:"networkConfigurations"`
	// The location of the Oracle Cluster Registry (OCR).
	OcrFileLocation *string `pulumi:"ocrFileLocation"`
	// The list of Single Client Access Name (SCAN) configurations of the external cluster.
	ScanConfigurations []ExternalClusterScanConfiguration `pulumi:"scanConfigurations"`
	// The current lifecycle state of the external cluster.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the external cluster was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the external cluster was last updated.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The cluster version.
	Version *string `pulumi:"version"`
	// The list of Virtual IP (VIP) configurations of the external cluster.
	VipConfigurations []ExternalClusterVipConfiguration `pulumi:"vipConfigurations"`
}

type ExternalClusterState struct {
	// The additional details of the external cluster defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails pulumi.StringMapInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// The name of the external cluster.
	ComponentName pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// The user-friendly name for the external cluster. The name does not have to be unique.
	DisplayName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
	ExternalClusterId pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster is a part of.
	ExternalDbSystemId pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// The directory in which Oracle Grid Infrastructure is installed.
	GridHome pulumi.StringPtrInput
	// Indicates whether the cluster is Oracle Flex Cluster or not.
	IsFlexCluster pulumi.BoolPtrInput
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringPtrInput
	// The list of network address configurations of the external cluster.
	NetworkConfigurations ExternalClusterNetworkConfigurationArrayInput
	// The location of the Oracle Cluster Registry (OCR).
	OcrFileLocation pulumi.StringPtrInput
	// The list of Single Client Access Name (SCAN) configurations of the external cluster.
	ScanConfigurations ExternalClusterScanConfigurationArrayInput
	// The current lifecycle state of the external cluster.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The date and time the external cluster was created.
	TimeCreated pulumi.StringPtrInput
	// The date and time the external cluster was last updated.
	TimeUpdated pulumi.StringPtrInput
	// The cluster version.
	Version pulumi.StringPtrInput
	// The list of Virtual IP (VIP) configurations of the external cluster.
	VipConfigurations ExternalClusterVipConfigurationArrayInput
}

func (ExternalClusterState) ElementType() reflect.Type {
	return reflect.TypeOf((*externalClusterState)(nil)).Elem()
}

type externalClusterArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
	ExternalClusterId string `pulumi:"externalClusterId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId *string `pulumi:"externalConnectorId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
}

// The set of arguments for constructing a ExternalCluster resource.
type ExternalClusterArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
	ExternalClusterId pulumi.StringInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
}

func (ExternalClusterArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*externalClusterArgs)(nil)).Elem()
}

type ExternalClusterInput interface {
	pulumi.Input

	ToExternalClusterOutput() ExternalClusterOutput
	ToExternalClusterOutputWithContext(ctx context.Context) ExternalClusterOutput
}

func (*ExternalCluster) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalCluster)(nil)).Elem()
}

func (i *ExternalCluster) ToExternalClusterOutput() ExternalClusterOutput {
	return i.ToExternalClusterOutputWithContext(context.Background())
}

func (i *ExternalCluster) ToExternalClusterOutputWithContext(ctx context.Context) ExternalClusterOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalClusterOutput)
}

// ExternalClusterArrayInput is an input type that accepts ExternalClusterArray and ExternalClusterArrayOutput values.
// You can construct a concrete instance of `ExternalClusterArrayInput` via:
//
//	ExternalClusterArray{ ExternalClusterArgs{...} }
type ExternalClusterArrayInput interface {
	pulumi.Input

	ToExternalClusterArrayOutput() ExternalClusterArrayOutput
	ToExternalClusterArrayOutputWithContext(context.Context) ExternalClusterArrayOutput
}

type ExternalClusterArray []ExternalClusterInput

func (ExternalClusterArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalCluster)(nil)).Elem()
}

func (i ExternalClusterArray) ToExternalClusterArrayOutput() ExternalClusterArrayOutput {
	return i.ToExternalClusterArrayOutputWithContext(context.Background())
}

func (i ExternalClusterArray) ToExternalClusterArrayOutputWithContext(ctx context.Context) ExternalClusterArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalClusterArrayOutput)
}

// ExternalClusterMapInput is an input type that accepts ExternalClusterMap and ExternalClusterMapOutput values.
// You can construct a concrete instance of `ExternalClusterMapInput` via:
//
//	ExternalClusterMap{ "key": ExternalClusterArgs{...} }
type ExternalClusterMapInput interface {
	pulumi.Input

	ToExternalClusterMapOutput() ExternalClusterMapOutput
	ToExternalClusterMapOutputWithContext(context.Context) ExternalClusterMapOutput
}

type ExternalClusterMap map[string]ExternalClusterInput

func (ExternalClusterMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalCluster)(nil)).Elem()
}

func (i ExternalClusterMap) ToExternalClusterMapOutput() ExternalClusterMapOutput {
	return i.ToExternalClusterMapOutputWithContext(context.Background())
}

func (i ExternalClusterMap) ToExternalClusterMapOutputWithContext(ctx context.Context) ExternalClusterMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalClusterMapOutput)
}

type ExternalClusterOutput struct{ *pulumi.OutputState }

func (ExternalClusterOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalCluster)(nil)).Elem()
}

func (o ExternalClusterOutput) ToExternalClusterOutput() ExternalClusterOutput {
	return o
}

func (o ExternalClusterOutput) ToExternalClusterOutputWithContext(ctx context.Context) ExternalClusterOutput {
	return o
}

// The additional details of the external cluster defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
func (o ExternalClusterOutput) AdditionalDetails() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringMapOutput { return v.AdditionalDetails }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o ExternalClusterOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// The name of the external cluster.
func (o ExternalClusterOutput) ComponentName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.ComponentName }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o ExternalClusterOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The user-friendly name for the external cluster. The name does not have to be unique.
func (o ExternalClusterOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
func (o ExternalClusterOutput) ExternalClusterId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.ExternalClusterId }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
func (o ExternalClusterOutput) ExternalConnectorId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.ExternalConnectorId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster is a part of.
func (o ExternalClusterOutput) ExternalDbSystemId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.ExternalDbSystemId }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ExternalClusterOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The directory in which Oracle Grid Infrastructure is installed.
func (o ExternalClusterOutput) GridHome() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.GridHome }).(pulumi.StringOutput)
}

// Indicates whether the cluster is Oracle Flex Cluster or not.
func (o ExternalClusterOutput) IsFlexCluster() pulumi.BoolOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.BoolOutput { return v.IsFlexCluster }).(pulumi.BoolOutput)
}

// Additional information about the current lifecycle state.
func (o ExternalClusterOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The list of network address configurations of the external cluster.
func (o ExternalClusterOutput) NetworkConfigurations() ExternalClusterNetworkConfigurationArrayOutput {
	return o.ApplyT(func(v *ExternalCluster) ExternalClusterNetworkConfigurationArrayOutput {
		return v.NetworkConfigurations
	}).(ExternalClusterNetworkConfigurationArrayOutput)
}

// The location of the Oracle Cluster Registry (OCR).
func (o ExternalClusterOutput) OcrFileLocation() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.OcrFileLocation }).(pulumi.StringOutput)
}

// The list of Single Client Access Name (SCAN) configurations of the external cluster.
func (o ExternalClusterOutput) ScanConfigurations() ExternalClusterScanConfigurationArrayOutput {
	return o.ApplyT(func(v *ExternalCluster) ExternalClusterScanConfigurationArrayOutput { return v.ScanConfigurations }).(ExternalClusterScanConfigurationArrayOutput)
}

// The current lifecycle state of the external cluster.
func (o ExternalClusterOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o ExternalClusterOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the external cluster was created.
func (o ExternalClusterOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the external cluster was last updated.
func (o ExternalClusterOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The cluster version.
func (o ExternalClusterOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalCluster) pulumi.StringOutput { return v.Version }).(pulumi.StringOutput)
}

// The list of Virtual IP (VIP) configurations of the external cluster.
func (o ExternalClusterOutput) VipConfigurations() ExternalClusterVipConfigurationArrayOutput {
	return o.ApplyT(func(v *ExternalCluster) ExternalClusterVipConfigurationArrayOutput { return v.VipConfigurations }).(ExternalClusterVipConfigurationArrayOutput)
}

type ExternalClusterArrayOutput struct{ *pulumi.OutputState }

func (ExternalClusterArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalCluster)(nil)).Elem()
}

func (o ExternalClusterArrayOutput) ToExternalClusterArrayOutput() ExternalClusterArrayOutput {
	return o
}

func (o ExternalClusterArrayOutput) ToExternalClusterArrayOutputWithContext(ctx context.Context) ExternalClusterArrayOutput {
	return o
}

func (o ExternalClusterArrayOutput) Index(i pulumi.IntInput) ExternalClusterOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ExternalCluster {
		return vs[0].([]*ExternalCluster)[vs[1].(int)]
	}).(ExternalClusterOutput)
}

type ExternalClusterMapOutput struct{ *pulumi.OutputState }

func (ExternalClusterMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalCluster)(nil)).Elem()
}

func (o ExternalClusterMapOutput) ToExternalClusterMapOutput() ExternalClusterMapOutput {
	return o
}

func (o ExternalClusterMapOutput) ToExternalClusterMapOutputWithContext(ctx context.Context) ExternalClusterMapOutput {
	return o
}

func (o ExternalClusterMapOutput) MapIndex(k pulumi.StringInput) ExternalClusterOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ExternalCluster {
		return vs[0].(map[string]*ExternalCluster)[vs[1].(string)]
	}).(ExternalClusterOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalClusterInput)(nil)).Elem(), &ExternalCluster{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalClusterArrayInput)(nil)).Elem(), ExternalClusterArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalClusterMapInput)(nil)).Elem(), ExternalClusterMap{})
	pulumi.RegisterOutputType(ExternalClusterOutput{})
	pulumi.RegisterOutputType(ExternalClusterArrayOutput{})
	pulumi.RegisterOutputType(ExternalClusterMapOutput{})
}
