// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package goldengate

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Deployment resource in Oracle Cloud Infrastructure Golden Gate service.
//
// Creates a new Deployment.
//
// ## Import
//
// Deployments can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:GoldenGate/deployment:Deployment test_deployment "id"
// ```
type Deployment struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The Minimum number of OCPUs to be made available for this Deployment.
	CpuCoreCount pulumi.IntOutput `pulumi:"cpuCoreCount"`
	// (Updatable) Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
	DeploymentBackupId pulumi.StringOutput `pulumi:"deploymentBackupId"`
	// The deployment type.
	DeploymentType pulumi.StringOutput `pulumi:"deploymentType"`
	// The URL of a resource.
	DeploymentUrl pulumi.StringOutput `pulumi:"deploymentUrl"`
	// (Updatable) Metadata about this specific object.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) An object's Display Name.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) A three-label Fully Qualified Domain Name (FQDN) for a resource.
	Fqdn pulumi.StringOutput `pulumi:"fqdn"`
	// (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) Indicates if auto scaling is enabled for the Deployment's CPU core count.
	IsAutoScalingEnabled pulumi.BoolOutput `pulumi:"isAutoScalingEnabled"`
	// True if all of the aggregate resources are working correctly.
	IsHealthy pulumi.BoolOutput `pulumi:"isHealthy"`
	// Indicates if the resource is the the latest available version.
	IsLatestVersion pulumi.BoolOutput `pulumi:"isLatestVersion"`
	// (Updatable) True if this object is publicly available.
	IsPublic pulumi.BoolOutput `pulumi:"isPublic"`
	// Indicator will be true if the amount of storage being utilized exceeds the allowable storage utilization limit.  Exceeding the limit may be an indication of a misconfiguration of the deployment's GoldenGate service.
	IsStorageUtilizationLimitExceeded pulumi.BoolOutput `pulumi:"isStorageUtilizationLimitExceeded"`
	// (Updatable) The Oracle license model that applies to a Deployment.
	LicenseModel pulumi.StringOutput `pulumi:"licenseModel"`
	// Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Possible GGS lifecycle sub-states.
	LifecycleSubState pulumi.StringOutput `pulumi:"lifecycleSubState"`
	// (Updatable) An array of [Network Security Group](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm) OCIDs used to define network access for a deployment.
	NsgIds pulumi.StringArrayOutput `pulumi:"nsgIds"`
	// (Updatable) Deployment Data for creating an OggDeployment
	OggData DeploymentOggDataOutput `pulumi:"oggData"`
	// The private IP address in the customer's VCN representing the access point for the associated endpoint service in the GoldenGate service VCN.
	PrivateIpAddress pulumi.StringOutput `pulumi:"privateIpAddress"`
	// The public IP address representing the access point for the Deployment.
	PublicIpAddress pulumi.StringOutput `pulumi:"publicIpAddress"`
	// Possible lifecycle states.
	State pulumi.StringOutput `pulumi:"state"`
	// The amount of storage being utilized (in bytes)
	StorageUtilizationInBytes pulumi.StringOutput `pulumi:"storageUtilizationInBytes"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet being referenced.
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The date the existing version in use will no longer be considered as usable and an upgrade will be required.  This date is typically 6 months after the version was released for use by GGS.  The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeUpgradeRequired pulumi.StringOutput `pulumi:"timeUpgradeRequired"`
}

// NewDeployment registers a new resource with the given unique name, arguments, and options.
func NewDeployment(ctx *pulumi.Context,
	name string, args *DeploymentArgs, opts ...pulumi.ResourceOption) (*Deployment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.CpuCoreCount == nil {
		return nil, errors.New("invalid value for required argument 'CpuCoreCount'")
	}
	if args.DeploymentType == nil {
		return nil, errors.New("invalid value for required argument 'DeploymentType'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.IsAutoScalingEnabled == nil {
		return nil, errors.New("invalid value for required argument 'IsAutoScalingEnabled'")
	}
	if args.LicenseModel == nil {
		return nil, errors.New("invalid value for required argument 'LicenseModel'")
	}
	if args.SubnetId == nil {
		return nil, errors.New("invalid value for required argument 'SubnetId'")
	}
	var resource Deployment
	err := ctx.RegisterResource("oci:GoldenGate/deployment:Deployment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDeployment gets an existing Deployment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDeployment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DeploymentState, opts ...pulumi.ResourceOption) (*Deployment, error) {
	var resource Deployment
	err := ctx.ReadResource("oci:GoldenGate/deployment:Deployment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Deployment resources.
type deploymentState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The Minimum number of OCPUs to be made available for this Deployment.
	CpuCoreCount *int `pulumi:"cpuCoreCount"`
	// (Updatable) Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
	DeploymentBackupId *string `pulumi:"deploymentBackupId"`
	// The deployment type.
	DeploymentType *string `pulumi:"deploymentType"`
	// The URL of a resource.
	DeploymentUrl *string `pulumi:"deploymentUrl"`
	// (Updatable) Metadata about this specific object.
	Description *string `pulumi:"description"`
	// (Updatable) An object's Display Name.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) A three-label Fully Qualified Domain Name (FQDN) for a resource.
	Fqdn *string `pulumi:"fqdn"`
	// (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Indicates if auto scaling is enabled for the Deployment's CPU core count.
	IsAutoScalingEnabled *bool `pulumi:"isAutoScalingEnabled"`
	// True if all of the aggregate resources are working correctly.
	IsHealthy *bool `pulumi:"isHealthy"`
	// Indicates if the resource is the the latest available version.
	IsLatestVersion *bool `pulumi:"isLatestVersion"`
	// (Updatable) True if this object is publicly available.
	IsPublic *bool `pulumi:"isPublic"`
	// Indicator will be true if the amount of storage being utilized exceeds the allowable storage utilization limit.  Exceeding the limit may be an indication of a misconfiguration of the deployment's GoldenGate service.
	IsStorageUtilizationLimitExceeded *bool `pulumi:"isStorageUtilizationLimitExceeded"`
	// (Updatable) The Oracle license model that applies to a Deployment.
	LicenseModel *string `pulumi:"licenseModel"`
	// Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Possible GGS lifecycle sub-states.
	LifecycleSubState *string `pulumi:"lifecycleSubState"`
	// (Updatable) An array of [Network Security Group](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm) OCIDs used to define network access for a deployment.
	NsgIds []string `pulumi:"nsgIds"`
	// (Updatable) Deployment Data for creating an OggDeployment
	OggData *DeploymentOggData `pulumi:"oggData"`
	// The private IP address in the customer's VCN representing the access point for the associated endpoint service in the GoldenGate service VCN.
	PrivateIpAddress *string `pulumi:"privateIpAddress"`
	// The public IP address representing the access point for the Deployment.
	PublicIpAddress *string `pulumi:"publicIpAddress"`
	// Possible lifecycle states.
	State *string `pulumi:"state"`
	// The amount of storage being utilized (in bytes)
	StorageUtilizationInBytes *string `pulumi:"storageUtilizationInBytes"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet being referenced.
	SubnetId *string `pulumi:"subnetId"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The date the existing version in use will no longer be considered as usable and an upgrade will be required.  This date is typically 6 months after the version was released for use by GGS.  The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeUpgradeRequired *string `pulumi:"timeUpgradeRequired"`
}

type DeploymentState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The Minimum number of OCPUs to be made available for this Deployment.
	CpuCoreCount pulumi.IntPtrInput
	// (Updatable) Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
	DeploymentBackupId pulumi.StringPtrInput
	// The deployment type.
	DeploymentType pulumi.StringPtrInput
	// The URL of a resource.
	DeploymentUrl pulumi.StringPtrInput
	// (Updatable) Metadata about this specific object.
	Description pulumi.StringPtrInput
	// (Updatable) An object's Display Name.
	DisplayName pulumi.StringPtrInput
	// (Updatable) A three-label Fully Qualified Domain Name (FQDN) for a resource.
	Fqdn pulumi.StringPtrInput
	// (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Indicates if auto scaling is enabled for the Deployment's CPU core count.
	IsAutoScalingEnabled pulumi.BoolPtrInput
	// True if all of the aggregate resources are working correctly.
	IsHealthy pulumi.BoolPtrInput
	// Indicates if the resource is the the latest available version.
	IsLatestVersion pulumi.BoolPtrInput
	// (Updatable) True if this object is publicly available.
	IsPublic pulumi.BoolPtrInput
	// Indicator will be true if the amount of storage being utilized exceeds the allowable storage utilization limit.  Exceeding the limit may be an indication of a misconfiguration of the deployment's GoldenGate service.
	IsStorageUtilizationLimitExceeded pulumi.BoolPtrInput
	// (Updatable) The Oracle license model that applies to a Deployment.
	LicenseModel pulumi.StringPtrInput
	// Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// Possible GGS lifecycle sub-states.
	LifecycleSubState pulumi.StringPtrInput
	// (Updatable) An array of [Network Security Group](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm) OCIDs used to define network access for a deployment.
	NsgIds pulumi.StringArrayInput
	// (Updatable) Deployment Data for creating an OggDeployment
	OggData DeploymentOggDataPtrInput
	// The private IP address in the customer's VCN representing the access point for the associated endpoint service in the GoldenGate service VCN.
	PrivateIpAddress pulumi.StringPtrInput
	// The public IP address representing the access point for the Deployment.
	PublicIpAddress pulumi.StringPtrInput
	// Possible lifecycle states.
	State pulumi.StringPtrInput
	// The amount of storage being utilized (in bytes)
	StorageUtilizationInBytes pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet being referenced.
	SubnetId pulumi.StringPtrInput
	// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags pulumi.MapInput
	// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeCreated pulumi.StringPtrInput
	// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeUpdated pulumi.StringPtrInput
	// The date the existing version in use will no longer be considered as usable and an upgrade will be required.  This date is typically 6 months after the version was released for use by GGS.  The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeUpgradeRequired pulumi.StringPtrInput
}

func (DeploymentState) ElementType() reflect.Type {
	return reflect.TypeOf((*deploymentState)(nil)).Elem()
}

type deploymentArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The Minimum number of OCPUs to be made available for this Deployment.
	CpuCoreCount int `pulumi:"cpuCoreCount"`
	// (Updatable) Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
	DeploymentBackupId *string `pulumi:"deploymentBackupId"`
	// The deployment type.
	DeploymentType string `pulumi:"deploymentType"`
	// (Updatable) Metadata about this specific object.
	Description *string `pulumi:"description"`
	// (Updatable) An object's Display Name.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) A three-label Fully Qualified Domain Name (FQDN) for a resource.
	Fqdn *string `pulumi:"fqdn"`
	// (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Indicates if auto scaling is enabled for the Deployment's CPU core count.
	IsAutoScalingEnabled bool `pulumi:"isAutoScalingEnabled"`
	// (Updatable) True if this object is publicly available.
	IsPublic *bool `pulumi:"isPublic"`
	// (Updatable) The Oracle license model that applies to a Deployment.
	LicenseModel string `pulumi:"licenseModel"`
	// (Updatable) An array of [Network Security Group](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm) OCIDs used to define network access for a deployment.
	NsgIds []string `pulumi:"nsgIds"`
	// (Updatable) Deployment Data for creating an OggDeployment
	OggData *DeploymentOggData `pulumi:"oggData"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet being referenced.
	SubnetId string `pulumi:"subnetId"`
}

// The set of arguments for constructing a Deployment resource.
type DeploymentArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
	CompartmentId pulumi.StringInput
	// (Updatable) The Minimum number of OCPUs to be made available for this Deployment.
	CpuCoreCount pulumi.IntInput
	// (Updatable) Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
	DeploymentBackupId pulumi.StringPtrInput
	// The deployment type.
	DeploymentType pulumi.StringInput
	// (Updatable) Metadata about this specific object.
	Description pulumi.StringPtrInput
	// (Updatable) An object's Display Name.
	DisplayName pulumi.StringInput
	// (Updatable) A three-label Fully Qualified Domain Name (FQDN) for a resource.
	Fqdn pulumi.StringPtrInput
	// (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Indicates if auto scaling is enabled for the Deployment's CPU core count.
	IsAutoScalingEnabled pulumi.BoolInput
	// (Updatable) True if this object is publicly available.
	IsPublic pulumi.BoolPtrInput
	// (Updatable) The Oracle license model that applies to a Deployment.
	LicenseModel pulumi.StringInput
	// (Updatable) An array of [Network Security Group](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm) OCIDs used to define network access for a deployment.
	NsgIds pulumi.StringArrayInput
	// (Updatable) Deployment Data for creating an OggDeployment
	OggData DeploymentOggDataPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet being referenced.
	SubnetId pulumi.StringInput
}

func (DeploymentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*deploymentArgs)(nil)).Elem()
}

type DeploymentInput interface {
	pulumi.Input

	ToDeploymentOutput() DeploymentOutput
	ToDeploymentOutputWithContext(ctx context.Context) DeploymentOutput
}

func (*Deployment) ElementType() reflect.Type {
	return reflect.TypeOf((**Deployment)(nil)).Elem()
}

func (i *Deployment) ToDeploymentOutput() DeploymentOutput {
	return i.ToDeploymentOutputWithContext(context.Background())
}

func (i *Deployment) ToDeploymentOutputWithContext(ctx context.Context) DeploymentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DeploymentOutput)
}

// DeploymentArrayInput is an input type that accepts DeploymentArray and DeploymentArrayOutput values.
// You can construct a concrete instance of `DeploymentArrayInput` via:
//
//          DeploymentArray{ DeploymentArgs{...} }
type DeploymentArrayInput interface {
	pulumi.Input

	ToDeploymentArrayOutput() DeploymentArrayOutput
	ToDeploymentArrayOutputWithContext(context.Context) DeploymentArrayOutput
}

type DeploymentArray []DeploymentInput

func (DeploymentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Deployment)(nil)).Elem()
}

func (i DeploymentArray) ToDeploymentArrayOutput() DeploymentArrayOutput {
	return i.ToDeploymentArrayOutputWithContext(context.Background())
}

func (i DeploymentArray) ToDeploymentArrayOutputWithContext(ctx context.Context) DeploymentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DeploymentArrayOutput)
}

// DeploymentMapInput is an input type that accepts DeploymentMap and DeploymentMapOutput values.
// You can construct a concrete instance of `DeploymentMapInput` via:
//
//          DeploymentMap{ "key": DeploymentArgs{...} }
type DeploymentMapInput interface {
	pulumi.Input

	ToDeploymentMapOutput() DeploymentMapOutput
	ToDeploymentMapOutputWithContext(context.Context) DeploymentMapOutput
}

type DeploymentMap map[string]DeploymentInput

func (DeploymentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Deployment)(nil)).Elem()
}

func (i DeploymentMap) ToDeploymentMapOutput() DeploymentMapOutput {
	return i.ToDeploymentMapOutputWithContext(context.Background())
}

func (i DeploymentMap) ToDeploymentMapOutputWithContext(ctx context.Context) DeploymentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DeploymentMapOutput)
}

type DeploymentOutput struct{ *pulumi.OutputState }

func (DeploymentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Deployment)(nil)).Elem()
}

func (o DeploymentOutput) ToDeploymentOutput() DeploymentOutput {
	return o
}

func (o DeploymentOutput) ToDeploymentOutputWithContext(ctx context.Context) DeploymentOutput {
	return o
}

type DeploymentArrayOutput struct{ *pulumi.OutputState }

func (DeploymentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Deployment)(nil)).Elem()
}

func (o DeploymentArrayOutput) ToDeploymentArrayOutput() DeploymentArrayOutput {
	return o
}

func (o DeploymentArrayOutput) ToDeploymentArrayOutputWithContext(ctx context.Context) DeploymentArrayOutput {
	return o
}

func (o DeploymentArrayOutput) Index(i pulumi.IntInput) DeploymentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Deployment {
		return vs[0].([]*Deployment)[vs[1].(int)]
	}).(DeploymentOutput)
}

type DeploymentMapOutput struct{ *pulumi.OutputState }

func (DeploymentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Deployment)(nil)).Elem()
}

func (o DeploymentMapOutput) ToDeploymentMapOutput() DeploymentMapOutput {
	return o
}

func (o DeploymentMapOutput) ToDeploymentMapOutputWithContext(ctx context.Context) DeploymentMapOutput {
	return o
}

func (o DeploymentMapOutput) MapIndex(k pulumi.StringInput) DeploymentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Deployment {
		return vs[0].(map[string]*Deployment)[vs[1].(string)]
	}).(DeploymentOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DeploymentInput)(nil)).Elem(), &Deployment{})
	pulumi.RegisterInputType(reflect.TypeOf((*DeploymentArrayInput)(nil)).Elem(), DeploymentArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DeploymentMapInput)(nil)).Elem(), DeploymentMap{})
	pulumi.RegisterOutputType(DeploymentOutput{})
	pulumi.RegisterOutputType(DeploymentArrayOutput{})
	pulumi.RegisterOutputType(DeploymentMapOutput{})
}
