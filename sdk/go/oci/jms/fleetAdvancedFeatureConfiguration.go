// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package jms

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Fleet Advanced Feature Configuration resource in Oracle Cloud Infrastructure Jms service.
//
// Update advanced feature configurations for the Fleet.
// Ensure that the namespace and bucket storage are created prior to turning on the JfrRecording or CryptoEventAnalysis feature.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/jms"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := jms.NewFleetAdvancedFeatureConfiguration(ctx, "test_fleet_advanced_feature_configuration", &jms.FleetAdvancedFeatureConfigurationArgs{
//				FleetId: pulumi.Any(testFleet.Id),
//				AdvancedUsageTracking: &jms.FleetAdvancedFeatureConfigurationAdvancedUsageTrackingArgs{
//					IsEnabled: pulumi.Any(fleetAdvancedFeatureConfigurationAdvancedUsageTrackingIsEnabled),
//				},
//				AnalyticBucketName: pulumi.Any(testBucket.Name),
//				AnalyticNamespace:  pulumi.Any(fleetAdvancedFeatureConfigurationAnalyticNamespace),
//				CryptoEventAnalysis: &jms.FleetAdvancedFeatureConfigurationCryptoEventAnalysisArgs{
//					IsEnabled: pulumi.Any(fleetAdvancedFeatureConfigurationCryptoEventAnalysisIsEnabled),
//					SummarizedEventsLog: &jms.FleetAdvancedFeatureConfigurationCryptoEventAnalysisSummarizedEventsLogArgs{
//						LogGroupId: pulumi.Any(testLogGroup.Id),
//						LogId:      pulumi.Any(testLog.Id),
//					},
//				},
//				JavaMigrationAnalysis: &jms.FleetAdvancedFeatureConfigurationJavaMigrationAnalysisArgs{
//					IsEnabled: pulumi.Any(fleetAdvancedFeatureConfigurationJavaMigrationAnalysisIsEnabled),
//				},
//				JfrRecording: &jms.FleetAdvancedFeatureConfigurationJfrRecordingArgs{
//					IsEnabled: pulumi.Any(fleetAdvancedFeatureConfigurationJfrRecordingIsEnabled),
//				},
//				Lcm: &jms.FleetAdvancedFeatureConfigurationLcmArgs{
//					IsEnabled: pulumi.Any(fleetAdvancedFeatureConfigurationLcmIsEnabled),
//					PostInstallationActions: &jms.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsArgs{
//						AddLoggingHandler:   pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsAddLoggingHandler),
//						DisabledTlsVersions: pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsDisabledTlsVersions),
//						GlobalLoggingLevel:  pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsGlobalLoggingLevel),
//						MinimumKeySizeSettings: &jms.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsArgs{
//							Certpaths: jms.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpathArray{
//								&jms.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpathArgs{
//									KeySize: pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpathKeySize),
//									Name:    pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpathName),
//								},
//							},
//							Jars: jms.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJarArray{
//								&jms.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJarArgs{
//									KeySize: pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJarKeySize),
//									Name:    pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJarName),
//								},
//							},
//							Tls: jms.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArray{
//								&jms.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs{
//									KeySize: pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlsKeySize),
//									Name:    pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlsName),
//								},
//							},
//						},
//						Proxies: &jms.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxiesArgs{
//							FtpProxyHost:     pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxiesFtpProxyHost),
//							FtpProxyPort:     pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxiesFtpProxyPort),
//							HttpProxyHost:    pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxiesHttpProxyHost),
//							HttpProxyPort:    pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxiesHttpProxyPort),
//							HttpsProxyHost:   pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxiesHttpsProxyHost),
//							HttpsProxyPort:   pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxiesHttpsProxyPort),
//							SocksProxyHost:   pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxiesSocksProxyHost),
//							SocksProxyPort:   pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxiesSocksProxyPort),
//							UseSystemProxies: pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxiesUseSystemProxies),
//						},
//						ShouldReplaceCertificatesOperatingSystem: pulumi.Any(fleetAdvancedFeatureConfigurationLcmPostInstallationActionsShouldReplaceCertificatesOperatingSystem),
//					},
//				},
//				PerformanceTuningAnalysis: &jms.FleetAdvancedFeatureConfigurationPerformanceTuningAnalysisArgs{
//					IsEnabled: pulumi.Any(fleetAdvancedFeatureConfigurationPerformanceTuningAnalysisIsEnabled),
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
// FleetAdvancedFeatureConfigurations can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Jms/fleetAdvancedFeatureConfiguration:FleetAdvancedFeatureConfiguration test_fleet_advanced_feature_configuration "fleets/{fleetId}/advancedFeatureConfiguration"
// ```
type FleetAdvancedFeatureConfiguration struct {
	pulumi.CustomResourceState

	// (Updatable) AdvancedUsageTracking configuration
	AdvancedUsageTracking FleetAdvancedFeatureConfigurationAdvancedUsageTrackingOutput `pulumi:"advancedUsageTracking"`
	// (Updatable) Bucket name required to store JFR and related data.
	AnalyticBucketName pulumi.StringOutput `pulumi:"analyticBucketName"`
	// (Updatable) Namespace for the Fleet advanced feature.
	AnalyticNamespace pulumi.StringOutput `pulumi:"analyticNamespace"`
	// (Updatable) CryptoEventAnalysis configuration
	CryptoEventAnalysis FleetAdvancedFeatureConfigurationCryptoEventAnalysisOutput `pulumi:"cryptoEventAnalysis"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
	FleetId pulumi.StringOutput `pulumi:"fleetId"`
	// (Updatable) JavaMigrationAnalysis configuration
	JavaMigrationAnalysis FleetAdvancedFeatureConfigurationJavaMigrationAnalysisOutput `pulumi:"javaMigrationAnalysis"`
	// (Updatable) JfrRecording configuration
	JfrRecording FleetAdvancedFeatureConfigurationJfrRecordingOutput `pulumi:"jfrRecording"`
	// (Updatable) Enable lifecycle management and set post action configurations.
	Lcm FleetAdvancedFeatureConfigurationLcmOutput `pulumi:"lcm"`
	// (Updatable) Performance tuning analysis configuration
	PerformanceTuningAnalysis FleetAdvancedFeatureConfigurationPerformanceTuningAnalysisOutput `pulumi:"performanceTuningAnalysis"`
	// The date and time of the last modification to the Fleet Agent Configuration (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeLastModified pulumi.StringOutput `pulumi:"timeLastModified"`
}

// NewFleetAdvancedFeatureConfiguration registers a new resource with the given unique name, arguments, and options.
func NewFleetAdvancedFeatureConfiguration(ctx *pulumi.Context,
	name string, args *FleetAdvancedFeatureConfigurationArgs, opts ...pulumi.ResourceOption) (*FleetAdvancedFeatureConfiguration, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.FleetId == nil {
		return nil, errors.New("invalid value for required argument 'FleetId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource FleetAdvancedFeatureConfiguration
	err := ctx.RegisterResource("oci:Jms/fleetAdvancedFeatureConfiguration:FleetAdvancedFeatureConfiguration", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetFleetAdvancedFeatureConfiguration gets an existing FleetAdvancedFeatureConfiguration resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetFleetAdvancedFeatureConfiguration(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *FleetAdvancedFeatureConfigurationState, opts ...pulumi.ResourceOption) (*FleetAdvancedFeatureConfiguration, error) {
	var resource FleetAdvancedFeatureConfiguration
	err := ctx.ReadResource("oci:Jms/fleetAdvancedFeatureConfiguration:FleetAdvancedFeatureConfiguration", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering FleetAdvancedFeatureConfiguration resources.
type fleetAdvancedFeatureConfigurationState struct {
	// (Updatable) AdvancedUsageTracking configuration
	AdvancedUsageTracking *FleetAdvancedFeatureConfigurationAdvancedUsageTracking `pulumi:"advancedUsageTracking"`
	// (Updatable) Bucket name required to store JFR and related data.
	AnalyticBucketName *string `pulumi:"analyticBucketName"`
	// (Updatable) Namespace for the Fleet advanced feature.
	AnalyticNamespace *string `pulumi:"analyticNamespace"`
	// (Updatable) CryptoEventAnalysis configuration
	CryptoEventAnalysis *FleetAdvancedFeatureConfigurationCryptoEventAnalysis `pulumi:"cryptoEventAnalysis"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
	FleetId *string `pulumi:"fleetId"`
	// (Updatable) JavaMigrationAnalysis configuration
	JavaMigrationAnalysis *FleetAdvancedFeatureConfigurationJavaMigrationAnalysis `pulumi:"javaMigrationAnalysis"`
	// (Updatable) JfrRecording configuration
	JfrRecording *FleetAdvancedFeatureConfigurationJfrRecording `pulumi:"jfrRecording"`
	// (Updatable) Enable lifecycle management and set post action configurations.
	Lcm *FleetAdvancedFeatureConfigurationLcm `pulumi:"lcm"`
	// (Updatable) Performance tuning analysis configuration
	PerformanceTuningAnalysis *FleetAdvancedFeatureConfigurationPerformanceTuningAnalysis `pulumi:"performanceTuningAnalysis"`
	// The date and time of the last modification to the Fleet Agent Configuration (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeLastModified *string `pulumi:"timeLastModified"`
}

type FleetAdvancedFeatureConfigurationState struct {
	// (Updatable) AdvancedUsageTracking configuration
	AdvancedUsageTracking FleetAdvancedFeatureConfigurationAdvancedUsageTrackingPtrInput
	// (Updatable) Bucket name required to store JFR and related data.
	AnalyticBucketName pulumi.StringPtrInput
	// (Updatable) Namespace for the Fleet advanced feature.
	AnalyticNamespace pulumi.StringPtrInput
	// (Updatable) CryptoEventAnalysis configuration
	CryptoEventAnalysis FleetAdvancedFeatureConfigurationCryptoEventAnalysisPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
	FleetId pulumi.StringPtrInput
	// (Updatable) JavaMigrationAnalysis configuration
	JavaMigrationAnalysis FleetAdvancedFeatureConfigurationJavaMigrationAnalysisPtrInput
	// (Updatable) JfrRecording configuration
	JfrRecording FleetAdvancedFeatureConfigurationJfrRecordingPtrInput
	// (Updatable) Enable lifecycle management and set post action configurations.
	Lcm FleetAdvancedFeatureConfigurationLcmPtrInput
	// (Updatable) Performance tuning analysis configuration
	PerformanceTuningAnalysis FleetAdvancedFeatureConfigurationPerformanceTuningAnalysisPtrInput
	// The date and time of the last modification to the Fleet Agent Configuration (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeLastModified pulumi.StringPtrInput
}

func (FleetAdvancedFeatureConfigurationState) ElementType() reflect.Type {
	return reflect.TypeOf((*fleetAdvancedFeatureConfigurationState)(nil)).Elem()
}

type fleetAdvancedFeatureConfigurationArgs struct {
	// (Updatable) AdvancedUsageTracking configuration
	AdvancedUsageTracking *FleetAdvancedFeatureConfigurationAdvancedUsageTracking `pulumi:"advancedUsageTracking"`
	// (Updatable) Bucket name required to store JFR and related data.
	AnalyticBucketName *string `pulumi:"analyticBucketName"`
	// (Updatable) Namespace for the Fleet advanced feature.
	AnalyticNamespace *string `pulumi:"analyticNamespace"`
	// (Updatable) CryptoEventAnalysis configuration
	CryptoEventAnalysis *FleetAdvancedFeatureConfigurationCryptoEventAnalysis `pulumi:"cryptoEventAnalysis"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
	FleetId string `pulumi:"fleetId"`
	// (Updatable) JavaMigrationAnalysis configuration
	JavaMigrationAnalysis *FleetAdvancedFeatureConfigurationJavaMigrationAnalysis `pulumi:"javaMigrationAnalysis"`
	// (Updatable) JfrRecording configuration
	JfrRecording *FleetAdvancedFeatureConfigurationJfrRecording `pulumi:"jfrRecording"`
	// (Updatable) Enable lifecycle management and set post action configurations.
	Lcm *FleetAdvancedFeatureConfigurationLcm `pulumi:"lcm"`
	// (Updatable) Performance tuning analysis configuration
	PerformanceTuningAnalysis *FleetAdvancedFeatureConfigurationPerformanceTuningAnalysis `pulumi:"performanceTuningAnalysis"`
}

// The set of arguments for constructing a FleetAdvancedFeatureConfiguration resource.
type FleetAdvancedFeatureConfigurationArgs struct {
	// (Updatable) AdvancedUsageTracking configuration
	AdvancedUsageTracking FleetAdvancedFeatureConfigurationAdvancedUsageTrackingPtrInput
	// (Updatable) Bucket name required to store JFR and related data.
	AnalyticBucketName pulumi.StringPtrInput
	// (Updatable) Namespace for the Fleet advanced feature.
	AnalyticNamespace pulumi.StringPtrInput
	// (Updatable) CryptoEventAnalysis configuration
	CryptoEventAnalysis FleetAdvancedFeatureConfigurationCryptoEventAnalysisPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
	FleetId pulumi.StringInput
	// (Updatable) JavaMigrationAnalysis configuration
	JavaMigrationAnalysis FleetAdvancedFeatureConfigurationJavaMigrationAnalysisPtrInput
	// (Updatable) JfrRecording configuration
	JfrRecording FleetAdvancedFeatureConfigurationJfrRecordingPtrInput
	// (Updatable) Enable lifecycle management and set post action configurations.
	Lcm FleetAdvancedFeatureConfigurationLcmPtrInput
	// (Updatable) Performance tuning analysis configuration
	PerformanceTuningAnalysis FleetAdvancedFeatureConfigurationPerformanceTuningAnalysisPtrInput
}

func (FleetAdvancedFeatureConfigurationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*fleetAdvancedFeatureConfigurationArgs)(nil)).Elem()
}

type FleetAdvancedFeatureConfigurationInput interface {
	pulumi.Input

	ToFleetAdvancedFeatureConfigurationOutput() FleetAdvancedFeatureConfigurationOutput
	ToFleetAdvancedFeatureConfigurationOutputWithContext(ctx context.Context) FleetAdvancedFeatureConfigurationOutput
}

func (*FleetAdvancedFeatureConfiguration) ElementType() reflect.Type {
	return reflect.TypeOf((**FleetAdvancedFeatureConfiguration)(nil)).Elem()
}

func (i *FleetAdvancedFeatureConfiguration) ToFleetAdvancedFeatureConfigurationOutput() FleetAdvancedFeatureConfigurationOutput {
	return i.ToFleetAdvancedFeatureConfigurationOutputWithContext(context.Background())
}

func (i *FleetAdvancedFeatureConfiguration) ToFleetAdvancedFeatureConfigurationOutputWithContext(ctx context.Context) FleetAdvancedFeatureConfigurationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FleetAdvancedFeatureConfigurationOutput)
}

// FleetAdvancedFeatureConfigurationArrayInput is an input type that accepts FleetAdvancedFeatureConfigurationArray and FleetAdvancedFeatureConfigurationArrayOutput values.
// You can construct a concrete instance of `FleetAdvancedFeatureConfigurationArrayInput` via:
//
//	FleetAdvancedFeatureConfigurationArray{ FleetAdvancedFeatureConfigurationArgs{...} }
type FleetAdvancedFeatureConfigurationArrayInput interface {
	pulumi.Input

	ToFleetAdvancedFeatureConfigurationArrayOutput() FleetAdvancedFeatureConfigurationArrayOutput
	ToFleetAdvancedFeatureConfigurationArrayOutputWithContext(context.Context) FleetAdvancedFeatureConfigurationArrayOutput
}

type FleetAdvancedFeatureConfigurationArray []FleetAdvancedFeatureConfigurationInput

func (FleetAdvancedFeatureConfigurationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*FleetAdvancedFeatureConfiguration)(nil)).Elem()
}

func (i FleetAdvancedFeatureConfigurationArray) ToFleetAdvancedFeatureConfigurationArrayOutput() FleetAdvancedFeatureConfigurationArrayOutput {
	return i.ToFleetAdvancedFeatureConfigurationArrayOutputWithContext(context.Background())
}

func (i FleetAdvancedFeatureConfigurationArray) ToFleetAdvancedFeatureConfigurationArrayOutputWithContext(ctx context.Context) FleetAdvancedFeatureConfigurationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FleetAdvancedFeatureConfigurationArrayOutput)
}

// FleetAdvancedFeatureConfigurationMapInput is an input type that accepts FleetAdvancedFeatureConfigurationMap and FleetAdvancedFeatureConfigurationMapOutput values.
// You can construct a concrete instance of `FleetAdvancedFeatureConfigurationMapInput` via:
//
//	FleetAdvancedFeatureConfigurationMap{ "key": FleetAdvancedFeatureConfigurationArgs{...} }
type FleetAdvancedFeatureConfigurationMapInput interface {
	pulumi.Input

	ToFleetAdvancedFeatureConfigurationMapOutput() FleetAdvancedFeatureConfigurationMapOutput
	ToFleetAdvancedFeatureConfigurationMapOutputWithContext(context.Context) FleetAdvancedFeatureConfigurationMapOutput
}

type FleetAdvancedFeatureConfigurationMap map[string]FleetAdvancedFeatureConfigurationInput

func (FleetAdvancedFeatureConfigurationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*FleetAdvancedFeatureConfiguration)(nil)).Elem()
}

func (i FleetAdvancedFeatureConfigurationMap) ToFleetAdvancedFeatureConfigurationMapOutput() FleetAdvancedFeatureConfigurationMapOutput {
	return i.ToFleetAdvancedFeatureConfigurationMapOutputWithContext(context.Background())
}

func (i FleetAdvancedFeatureConfigurationMap) ToFleetAdvancedFeatureConfigurationMapOutputWithContext(ctx context.Context) FleetAdvancedFeatureConfigurationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FleetAdvancedFeatureConfigurationMapOutput)
}

type FleetAdvancedFeatureConfigurationOutput struct{ *pulumi.OutputState }

func (FleetAdvancedFeatureConfigurationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**FleetAdvancedFeatureConfiguration)(nil)).Elem()
}

func (o FleetAdvancedFeatureConfigurationOutput) ToFleetAdvancedFeatureConfigurationOutput() FleetAdvancedFeatureConfigurationOutput {
	return o
}

func (o FleetAdvancedFeatureConfigurationOutput) ToFleetAdvancedFeatureConfigurationOutputWithContext(ctx context.Context) FleetAdvancedFeatureConfigurationOutput {
	return o
}

// (Updatable) AdvancedUsageTracking configuration
func (o FleetAdvancedFeatureConfigurationOutput) AdvancedUsageTracking() FleetAdvancedFeatureConfigurationAdvancedUsageTrackingOutput {
	return o.ApplyT(func(v *FleetAdvancedFeatureConfiguration) FleetAdvancedFeatureConfigurationAdvancedUsageTrackingOutput {
		return v.AdvancedUsageTracking
	}).(FleetAdvancedFeatureConfigurationAdvancedUsageTrackingOutput)
}

// (Updatable) Bucket name required to store JFR and related data.
func (o FleetAdvancedFeatureConfigurationOutput) AnalyticBucketName() pulumi.StringOutput {
	return o.ApplyT(func(v *FleetAdvancedFeatureConfiguration) pulumi.StringOutput { return v.AnalyticBucketName }).(pulumi.StringOutput)
}

// (Updatable) Namespace for the Fleet advanced feature.
func (o FleetAdvancedFeatureConfigurationOutput) AnalyticNamespace() pulumi.StringOutput {
	return o.ApplyT(func(v *FleetAdvancedFeatureConfiguration) pulumi.StringOutput { return v.AnalyticNamespace }).(pulumi.StringOutput)
}

// (Updatable) CryptoEventAnalysis configuration
func (o FleetAdvancedFeatureConfigurationOutput) CryptoEventAnalysis() FleetAdvancedFeatureConfigurationCryptoEventAnalysisOutput {
	return o.ApplyT(func(v *FleetAdvancedFeatureConfiguration) FleetAdvancedFeatureConfigurationCryptoEventAnalysisOutput {
		return v.CryptoEventAnalysis
	}).(FleetAdvancedFeatureConfigurationCryptoEventAnalysisOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
func (o FleetAdvancedFeatureConfigurationOutput) FleetId() pulumi.StringOutput {
	return o.ApplyT(func(v *FleetAdvancedFeatureConfiguration) pulumi.StringOutput { return v.FleetId }).(pulumi.StringOutput)
}

// (Updatable) JavaMigrationAnalysis configuration
func (o FleetAdvancedFeatureConfigurationOutput) JavaMigrationAnalysis() FleetAdvancedFeatureConfigurationJavaMigrationAnalysisOutput {
	return o.ApplyT(func(v *FleetAdvancedFeatureConfiguration) FleetAdvancedFeatureConfigurationJavaMigrationAnalysisOutput {
		return v.JavaMigrationAnalysis
	}).(FleetAdvancedFeatureConfigurationJavaMigrationAnalysisOutput)
}

// (Updatable) JfrRecording configuration
func (o FleetAdvancedFeatureConfigurationOutput) JfrRecording() FleetAdvancedFeatureConfigurationJfrRecordingOutput {
	return o.ApplyT(func(v *FleetAdvancedFeatureConfiguration) FleetAdvancedFeatureConfigurationJfrRecordingOutput {
		return v.JfrRecording
	}).(FleetAdvancedFeatureConfigurationJfrRecordingOutput)
}

// (Updatable) Enable lifecycle management and set post action configurations.
func (o FleetAdvancedFeatureConfigurationOutput) Lcm() FleetAdvancedFeatureConfigurationLcmOutput {
	return o.ApplyT(func(v *FleetAdvancedFeatureConfiguration) FleetAdvancedFeatureConfigurationLcmOutput { return v.Lcm }).(FleetAdvancedFeatureConfigurationLcmOutput)
}

// (Updatable) Performance tuning analysis configuration
func (o FleetAdvancedFeatureConfigurationOutput) PerformanceTuningAnalysis() FleetAdvancedFeatureConfigurationPerformanceTuningAnalysisOutput {
	return o.ApplyT(func(v *FleetAdvancedFeatureConfiguration) FleetAdvancedFeatureConfigurationPerformanceTuningAnalysisOutput {
		return v.PerformanceTuningAnalysis
	}).(FleetAdvancedFeatureConfigurationPerformanceTuningAnalysisOutput)
}

// The date and time of the last modification to the Fleet Agent Configuration (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
func (o FleetAdvancedFeatureConfigurationOutput) TimeLastModified() pulumi.StringOutput {
	return o.ApplyT(func(v *FleetAdvancedFeatureConfiguration) pulumi.StringOutput { return v.TimeLastModified }).(pulumi.StringOutput)
}

type FleetAdvancedFeatureConfigurationArrayOutput struct{ *pulumi.OutputState }

func (FleetAdvancedFeatureConfigurationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*FleetAdvancedFeatureConfiguration)(nil)).Elem()
}

func (o FleetAdvancedFeatureConfigurationArrayOutput) ToFleetAdvancedFeatureConfigurationArrayOutput() FleetAdvancedFeatureConfigurationArrayOutput {
	return o
}

func (o FleetAdvancedFeatureConfigurationArrayOutput) ToFleetAdvancedFeatureConfigurationArrayOutputWithContext(ctx context.Context) FleetAdvancedFeatureConfigurationArrayOutput {
	return o
}

func (o FleetAdvancedFeatureConfigurationArrayOutput) Index(i pulumi.IntInput) FleetAdvancedFeatureConfigurationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *FleetAdvancedFeatureConfiguration {
		return vs[0].([]*FleetAdvancedFeatureConfiguration)[vs[1].(int)]
	}).(FleetAdvancedFeatureConfigurationOutput)
}

type FleetAdvancedFeatureConfigurationMapOutput struct{ *pulumi.OutputState }

func (FleetAdvancedFeatureConfigurationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*FleetAdvancedFeatureConfiguration)(nil)).Elem()
}

func (o FleetAdvancedFeatureConfigurationMapOutput) ToFleetAdvancedFeatureConfigurationMapOutput() FleetAdvancedFeatureConfigurationMapOutput {
	return o
}

func (o FleetAdvancedFeatureConfigurationMapOutput) ToFleetAdvancedFeatureConfigurationMapOutputWithContext(ctx context.Context) FleetAdvancedFeatureConfigurationMapOutput {
	return o
}

func (o FleetAdvancedFeatureConfigurationMapOutput) MapIndex(k pulumi.StringInput) FleetAdvancedFeatureConfigurationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *FleetAdvancedFeatureConfiguration {
		return vs[0].(map[string]*FleetAdvancedFeatureConfiguration)[vs[1].(string)]
	}).(FleetAdvancedFeatureConfigurationOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*FleetAdvancedFeatureConfigurationInput)(nil)).Elem(), &FleetAdvancedFeatureConfiguration{})
	pulumi.RegisterInputType(reflect.TypeOf((*FleetAdvancedFeatureConfigurationArrayInput)(nil)).Elem(), FleetAdvancedFeatureConfigurationArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*FleetAdvancedFeatureConfigurationMapInput)(nil)).Elem(), FleetAdvancedFeatureConfigurationMap{})
	pulumi.RegisterOutputType(FleetAdvancedFeatureConfigurationOutput{})
	pulumi.RegisterOutputType(FleetAdvancedFeatureConfigurationArrayOutput{})
	pulumi.RegisterOutputType(FleetAdvancedFeatureConfigurationMapOutput{})
}
