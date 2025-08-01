// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package fleetappsmanagement

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Runbook Version resource in Oracle Cloud Infrastructure Fleet Apps Management service.
//
// Add RunbookVersion in Fleet Application Management.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/fleetappsmanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := fleetappsmanagement.NewRunbookVersion(ctx, "test_runbook_version", &fleetappsmanagement.RunbookVersionArgs{
//				ExecutionWorkflowDetails: &fleetappsmanagement.RunbookVersionExecutionWorkflowDetailsArgs{
//					Workflows: fleetappsmanagement.RunbookVersionExecutionWorkflowDetailsWorkflowArray{
//						&fleetappsmanagement.RunbookVersionExecutionWorkflowDetailsWorkflowArgs{
//							GroupName: pulumi.Any(testGroup.Name),
//							Steps: fleetappsmanagement.RunbookVersionExecutionWorkflowDetailsWorkflowStepArray{
//								&fleetappsmanagement.RunbookVersionExecutionWorkflowDetailsWorkflowStepArgs{
//									Type:      pulumi.Any(runbookVersionExecutionWorkflowDetailsWorkflowStepsType),
//									GroupName: pulumi.Any(testGroup.Name),
//									StepName:  pulumi.Any(runbookVersionExecutionWorkflowDetailsWorkflowStepsStepName),
//									Steps:     pulumi.Any(runbookVersionExecutionWorkflowDetailsWorkflowStepsSteps),
//								},
//							},
//							Type: pulumi.Any(runbookVersionExecutionWorkflowDetailsWorkflowType),
//						},
//					},
//				},
//				Groups: fleetappsmanagement.RunbookVersionGroupArray{
//					&fleetappsmanagement.RunbookVersionGroupArgs{
//						Name: pulumi.Any(runbookVersionGroupsName),
//						Type: pulumi.Any(runbookVersionGroupsType),
//						Properties: &fleetappsmanagement.RunbookVersionGroupPropertiesArgs{
//							ActionOnFailure: pulumi.Any(runbookVersionGroupsPropertiesActionOnFailure),
//							NotificationPreferences: &fleetappsmanagement.RunbookVersionGroupPropertiesNotificationPreferencesArgs{
//								ShouldNotifyOnPause:       pulumi.Any(runbookVersionGroupsPropertiesNotificationPreferencesShouldNotifyOnPause),
//								ShouldNotifyOnTaskFailure: pulumi.Any(runbookVersionGroupsPropertiesNotificationPreferencesShouldNotifyOnTaskFailure),
//								ShouldNotifyOnTaskSuccess: pulumi.Any(runbookVersionGroupsPropertiesNotificationPreferencesShouldNotifyOnTaskSuccess),
//							},
//							PauseDetails: &fleetappsmanagement.RunbookVersionGroupPropertiesPauseDetailsArgs{
//								Kind:              pulumi.Any(runbookVersionGroupsPropertiesPauseDetailsKind),
//								DurationInMinutes: pulumi.Any(runbookVersionGroupsPropertiesPauseDetailsDurationInMinutes),
//							},
//							PreCondition: pulumi.Any(runbookVersionGroupsPropertiesPreCondition),
//							RunOn: &fleetappsmanagement.RunbookVersionGroupPropertiesRunOnArgs{
//								Kind:      pulumi.Any(runbookVersionGroupsPropertiesRunOnKind),
//								Condition: pulumi.Any(runbookVersionGroupsPropertiesRunOnCondition),
//								Host:      pulumi.Any(runbookVersionGroupsPropertiesRunOnHost),
//								PreviousTaskInstanceDetails: fleetappsmanagement.RunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetailArray{
//									&fleetappsmanagement.RunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetailArgs{
//										OutputVariableDetails: &fleetappsmanagement.RunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetailsArgs{
//											OutputVariableName: pulumi.Any(runbookVersionGroupsPropertiesRunOnPreviousTaskInstanceDetailsOutputVariableDetailsOutputVariableName),
//											StepName:           pulumi.Any(runbookVersionGroupsPropertiesRunOnPreviousTaskInstanceDetailsOutputVariableDetailsStepName),
//										},
//										ResourceId:   pulumi.Any(testResource.Id),
//										ResourceType: pulumi.Any(runbookVersionGroupsPropertiesRunOnPreviousTaskInstanceDetailsResourceType),
//									},
//								},
//							},
//						},
//					},
//				},
//				RunbookId: pulumi.Any(testRunbook.Id),
//				Tasks: fleetappsmanagement.RunbookVersionTaskArray{
//					&fleetappsmanagement.RunbookVersionTaskArgs{
//						StepName: pulumi.Any(runbookVersionTasksStepName),
//						TaskRecordDetails: &fleetappsmanagement.RunbookVersionTaskTaskRecordDetailsArgs{
//							Scope:       pulumi.Any(runbookVersionTasksTaskRecordDetailsScope),
//							Description: pulumi.Any(runbookVersionTasksTaskRecordDetailsDescription),
//							ExecutionDetails: &fleetappsmanagement.RunbookVersionTaskTaskRecordDetailsExecutionDetailsArgs{
//								ExecutionType: pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsExecutionType),
//								CatalogId:     pulumi.Any(testCatalog.Id),
//								Command:       pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsCommand),
//								ConfigFile:    pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsConfigFile),
//								Content: &fleetappsmanagement.RunbookVersionTaskTaskRecordDetailsExecutionDetailsContentArgs{
//									SourceType: pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsContentSourceType),
//									Bucket:     pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsContentBucket),
//									CatalogId:  pulumi.Any(testCatalog.Id),
//									Checksum:   pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsContentChecksum),
//									Namespace:  pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsContentNamespace),
//									Object:     pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsContentObject),
//								},
//								Credentials: fleetappsmanagement.RunbookVersionTaskTaskRecordDetailsExecutionDetailsCredentialArray{
//									&fleetappsmanagement.RunbookVersionTaskTaskRecordDetailsExecutionDetailsCredentialArgs{
//										DisplayName: pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsCredentialsDisplayName),
//										Id:          pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsCredentialsId),
//									},
//								},
//								Endpoint:                    pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsEndpoint),
//								IsExecutableContent:         pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsIsExecutableContent),
//								IsLocked:                    pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsIsLocked),
//								IsReadOutputVariableEnabled: pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsIsReadOutputVariableEnabled),
//								TargetCompartmentId:         pulumi.Any(testCompartment.Id),
//								Variables: &fleetappsmanagement.RunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesArgs{
//									InputVariables: fleetappsmanagement.RunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariableArray{
//										&fleetappsmanagement.RunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariableArgs{
//											Description: pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsVariablesInputVariablesDescription),
//											Name:        pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsVariablesInputVariablesName),
//											Type:        pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsVariablesInputVariablesType),
//										},
//									},
//									OutputVariables: pulumi.Any(runbookVersionTasksTaskRecordDetailsExecutionDetailsVariablesOutputVariables),
//								},
//							},
//							IsApplySubjectTask:     pulumi.Any(runbookVersionTasksTaskRecordDetailsIsApplySubjectTask),
//							IsCopyToLibraryEnabled: pulumi.Any(runbookVersionTasksTaskRecordDetailsIsCopyToLibraryEnabled),
//							IsDiscoveryOutputTask:  pulumi.Any(runbookVersionTasksTaskRecordDetailsIsDiscoveryOutputTask),
//							Name:                   pulumi.Any(runbookVersionTasksTaskRecordDetailsName),
//							OsType:                 pulumi.Any(runbookVersionTasksTaskRecordDetailsOsType),
//							Platform:               pulumi.Any(runbookVersionTasksTaskRecordDetailsPlatform),
//							Properties: &fleetappsmanagement.RunbookVersionTaskTaskRecordDetailsPropertiesArgs{
//								NumRetries:       pulumi.Any(runbookVersionTasksTaskRecordDetailsPropertiesNumRetries),
//								TimeoutInSeconds: pulumi.Any(runbookVersionTasksTaskRecordDetailsPropertiesTimeoutInSeconds),
//							},
//							TaskRecordId: pulumi.Any(testTaskRecord.Id),
//						},
//						OutputVariableMappings: fleetappsmanagement.RunbookVersionTaskOutputVariableMappingArray{
//							&fleetappsmanagement.RunbookVersionTaskOutputVariableMappingArgs{
//								Name: pulumi.Any(runbookVersionTasksOutputVariableMappingsName),
//								OutputVariableDetails: &fleetappsmanagement.RunbookVersionTaskOutputVariableMappingOutputVariableDetailsArgs{
//									OutputVariableName: pulumi.Any(runbookVersionTasksOutputVariableMappingsOutputVariableDetailsOutputVariableName),
//									StepName:           pulumi.Any(runbookVersionTasksOutputVariableMappingsOutputVariableDetailsStepName),
//								},
//							},
//						},
//						StepProperties: &fleetappsmanagement.RunbookVersionTaskStepPropertiesArgs{
//							ActionOnFailure: pulumi.Any(runbookVersionTasksStepPropertiesActionOnFailure),
//							NotificationPreferences: &fleetappsmanagement.RunbookVersionTaskStepPropertiesNotificationPreferencesArgs{
//								ShouldNotifyOnPause:       pulumi.Any(runbookVersionTasksStepPropertiesNotificationPreferencesShouldNotifyOnPause),
//								ShouldNotifyOnTaskFailure: pulumi.Any(runbookVersionTasksStepPropertiesNotificationPreferencesShouldNotifyOnTaskFailure),
//								ShouldNotifyOnTaskSuccess: pulumi.Any(runbookVersionTasksStepPropertiesNotificationPreferencesShouldNotifyOnTaskSuccess),
//							},
//							PauseDetails: &fleetappsmanagement.RunbookVersionTaskStepPropertiesPauseDetailsArgs{
//								Kind:              pulumi.Any(runbookVersionTasksStepPropertiesPauseDetailsKind),
//								DurationInMinutes: pulumi.Any(runbookVersionTasksStepPropertiesPauseDetailsDurationInMinutes),
//							},
//							PreCondition: pulumi.Any(runbookVersionTasksStepPropertiesPreCondition),
//							RunOn: &fleetappsmanagement.RunbookVersionTaskStepPropertiesRunOnArgs{
//								Kind:      pulumi.Any(runbookVersionTasksStepPropertiesRunOnKind),
//								Condition: pulumi.Any(runbookVersionTasksStepPropertiesRunOnCondition),
//								Host:      pulumi.Any(runbookVersionTasksStepPropertiesRunOnHost),
//								PreviousTaskInstanceDetails: fleetappsmanagement.RunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailArray{
//									&fleetappsmanagement.RunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailArgs{
//										OutputVariableDetails: &fleetappsmanagement.RunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetailsArgs{
//											OutputVariableName: pulumi.Any(runbookVersionTasksStepPropertiesRunOnPreviousTaskInstanceDetailsOutputVariableDetailsOutputVariableName),
//											StepName:           pulumi.Any(runbookVersionTasksStepPropertiesRunOnPreviousTaskInstanceDetailsOutputVariableDetailsStepName),
//										},
//										ResourceId:   pulumi.Any(testResource.Id),
//										ResourceType: pulumi.Any(runbookVersionTasksStepPropertiesRunOnPreviousTaskInstanceDetailsResourceType),
//									},
//								},
//							},
//						},
//					},
//				},
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				RollbackWorkflowDetails: &fleetappsmanagement.RunbookVersionRollbackWorkflowDetailsArgs{
//					Scope: pulumi.Any(runbookVersionRollbackWorkflowDetailsScope),
//					Workflows: fleetappsmanagement.RunbookVersionRollbackWorkflowDetailsWorkflowArray{
//						&fleetappsmanagement.RunbookVersionRollbackWorkflowDetailsWorkflowArgs{
//							GroupName: pulumi.Any(testGroup.Name),
//							Steps: fleetappsmanagement.RunbookVersionRollbackWorkflowDetailsWorkflowStepArray{
//								&fleetappsmanagement.RunbookVersionRollbackWorkflowDetailsWorkflowStepArgs{
//									Type:      pulumi.Any(runbookVersionRollbackWorkflowDetailsWorkflowStepsType),
//									GroupName: pulumi.Any(testGroup.Name),
//									StepName:  pulumi.Any(runbookVersionRollbackWorkflowDetailsWorkflowStepsStepName),
//									Steps:     pulumi.Any(runbookVersionRollbackWorkflowDetailsWorkflowStepsSteps),
//								},
//							},
//							Type: pulumi.Any(runbookVersionRollbackWorkflowDetailsWorkflowType),
//						},
//					},
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
// RunbookVersions can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:FleetAppsManagement/runbookVersion:RunbookVersion test_runbook_version "id"
// ```
type RunbookVersion struct {
	pulumi.CustomResourceState

	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example:
	// `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Execution Workflow details.
	ExecutionWorkflowDetails RunbookVersionExecutionWorkflowDetailsOutput `pulumi:"executionWorkflowDetails"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists
	// for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// (Updatable) The groups of the runbook.
	Groups   RunbookVersionGroupArrayOutput `pulumi:"groups"`
	IsLatest pulumi.BoolOutput              `pulumi:"isLatest"`
	// A message describing the current state in more detail. For example, can be used to provide
	// actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The name of the task
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) Rollback Workflow details.
	RollbackWorkflowDetails RunbookVersionRollbackWorkflowDetailsOutput `pulumi:"rollbackWorkflowDetails"`
	// The OCID of the resource.
	RunbookId pulumi.StringOutput `pulumi:"runbookId"`
	// The current state of the FleetResource.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example:
	// `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// (Updatable) A set of tasks to execute in the runbook.
	Tasks RunbookVersionTaskArrayOutput `pulumi:"tasks"`
	// The time this resource was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time this resource was last updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewRunbookVersion registers a new resource with the given unique name, arguments, and options.
func NewRunbookVersion(ctx *pulumi.Context,
	name string, args *RunbookVersionArgs, opts ...pulumi.ResourceOption) (*RunbookVersion, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ExecutionWorkflowDetails == nil {
		return nil, errors.New("invalid value for required argument 'ExecutionWorkflowDetails'")
	}
	if args.Groups == nil {
		return nil, errors.New("invalid value for required argument 'Groups'")
	}
	if args.RunbookId == nil {
		return nil, errors.New("invalid value for required argument 'RunbookId'")
	}
	if args.Tasks == nil {
		return nil, errors.New("invalid value for required argument 'Tasks'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource RunbookVersion
	err := ctx.RegisterResource("oci:FleetAppsManagement/runbookVersion:RunbookVersion", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetRunbookVersion gets an existing RunbookVersion resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetRunbookVersion(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *RunbookVersionState, opts ...pulumi.ResourceOption) (*RunbookVersion, error) {
	var resource RunbookVersion
	err := ctx.ReadResource("oci:FleetAppsManagement/runbookVersion:RunbookVersion", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering RunbookVersion resources.
type runbookVersionState struct {
	CompartmentId *string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example:
	// `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Execution Workflow details.
	ExecutionWorkflowDetails *RunbookVersionExecutionWorkflowDetails `pulumi:"executionWorkflowDetails"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists
	// for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The groups of the runbook.
	Groups   []RunbookVersionGroup `pulumi:"groups"`
	IsLatest *bool                 `pulumi:"isLatest"`
	// A message describing the current state in more detail. For example, can be used to provide
	// actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The name of the task
	Name *string `pulumi:"name"`
	// (Updatable) Rollback Workflow details.
	RollbackWorkflowDetails *RunbookVersionRollbackWorkflowDetails `pulumi:"rollbackWorkflowDetails"`
	// The OCID of the resource.
	RunbookId *string `pulumi:"runbookId"`
	// The current state of the FleetResource.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example:
	// `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// (Updatable) A set of tasks to execute in the runbook.
	Tasks []RunbookVersionTask `pulumi:"tasks"`
	// The time this resource was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time this resource was last updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type RunbookVersionState struct {
	CompartmentId pulumi.StringPtrInput
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example:
	// `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Execution Workflow details.
	ExecutionWorkflowDetails RunbookVersionExecutionWorkflowDetailsPtrInput
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists
	// for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The groups of the runbook.
	Groups   RunbookVersionGroupArrayInput
	IsLatest pulumi.BoolPtrInput
	// A message describing the current state in more detail. For example, can be used to provide
	// actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The name of the task
	Name pulumi.StringPtrInput
	// (Updatable) Rollback Workflow details.
	RollbackWorkflowDetails RunbookVersionRollbackWorkflowDetailsPtrInput
	// The OCID of the resource.
	RunbookId pulumi.StringPtrInput
	// The current state of the FleetResource.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example:
	// `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// (Updatable) A set of tasks to execute in the runbook.
	Tasks RunbookVersionTaskArrayInput
	// The time this resource was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time this resource was last updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (RunbookVersionState) ElementType() reflect.Type {
	return reflect.TypeOf((*runbookVersionState)(nil)).Elem()
}

type runbookVersionArgs struct {
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example:
	// `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Execution Workflow details.
	ExecutionWorkflowDetails RunbookVersionExecutionWorkflowDetails `pulumi:"executionWorkflowDetails"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists
	// for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The groups of the runbook.
	Groups []RunbookVersionGroup `pulumi:"groups"`
	// (Updatable) Rollback Workflow details.
	RollbackWorkflowDetails *RunbookVersionRollbackWorkflowDetails `pulumi:"rollbackWorkflowDetails"`
	// The OCID of the resource.
	RunbookId string `pulumi:"runbookId"`
	// (Updatable) A set of tasks to execute in the runbook.
	Tasks []RunbookVersionTask `pulumi:"tasks"`
}

// The set of arguments for constructing a RunbookVersion resource.
type RunbookVersionArgs struct {
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example:
	// `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Execution Workflow details.
	ExecutionWorkflowDetails RunbookVersionExecutionWorkflowDetailsInput
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists
	// for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The groups of the runbook.
	Groups RunbookVersionGroupArrayInput
	// (Updatable) Rollback Workflow details.
	RollbackWorkflowDetails RunbookVersionRollbackWorkflowDetailsPtrInput
	// The OCID of the resource.
	RunbookId pulumi.StringInput
	// (Updatable) A set of tasks to execute in the runbook.
	Tasks RunbookVersionTaskArrayInput
}

func (RunbookVersionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*runbookVersionArgs)(nil)).Elem()
}

type RunbookVersionInput interface {
	pulumi.Input

	ToRunbookVersionOutput() RunbookVersionOutput
	ToRunbookVersionOutputWithContext(ctx context.Context) RunbookVersionOutput
}

func (*RunbookVersion) ElementType() reflect.Type {
	return reflect.TypeOf((**RunbookVersion)(nil)).Elem()
}

func (i *RunbookVersion) ToRunbookVersionOutput() RunbookVersionOutput {
	return i.ToRunbookVersionOutputWithContext(context.Background())
}

func (i *RunbookVersion) ToRunbookVersionOutputWithContext(ctx context.Context) RunbookVersionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RunbookVersionOutput)
}

// RunbookVersionArrayInput is an input type that accepts RunbookVersionArray and RunbookVersionArrayOutput values.
// You can construct a concrete instance of `RunbookVersionArrayInput` via:
//
//	RunbookVersionArray{ RunbookVersionArgs{...} }
type RunbookVersionArrayInput interface {
	pulumi.Input

	ToRunbookVersionArrayOutput() RunbookVersionArrayOutput
	ToRunbookVersionArrayOutputWithContext(context.Context) RunbookVersionArrayOutput
}

type RunbookVersionArray []RunbookVersionInput

func (RunbookVersionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*RunbookVersion)(nil)).Elem()
}

func (i RunbookVersionArray) ToRunbookVersionArrayOutput() RunbookVersionArrayOutput {
	return i.ToRunbookVersionArrayOutputWithContext(context.Background())
}

func (i RunbookVersionArray) ToRunbookVersionArrayOutputWithContext(ctx context.Context) RunbookVersionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RunbookVersionArrayOutput)
}

// RunbookVersionMapInput is an input type that accepts RunbookVersionMap and RunbookVersionMapOutput values.
// You can construct a concrete instance of `RunbookVersionMapInput` via:
//
//	RunbookVersionMap{ "key": RunbookVersionArgs{...} }
type RunbookVersionMapInput interface {
	pulumi.Input

	ToRunbookVersionMapOutput() RunbookVersionMapOutput
	ToRunbookVersionMapOutputWithContext(context.Context) RunbookVersionMapOutput
}

type RunbookVersionMap map[string]RunbookVersionInput

func (RunbookVersionMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*RunbookVersion)(nil)).Elem()
}

func (i RunbookVersionMap) ToRunbookVersionMapOutput() RunbookVersionMapOutput {
	return i.ToRunbookVersionMapOutputWithContext(context.Background())
}

func (i RunbookVersionMap) ToRunbookVersionMapOutputWithContext(ctx context.Context) RunbookVersionMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RunbookVersionMapOutput)
}

type RunbookVersionOutput struct{ *pulumi.OutputState }

func (RunbookVersionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**RunbookVersion)(nil)).Elem()
}

func (o RunbookVersionOutput) ToRunbookVersionOutput() RunbookVersionOutput {
	return o
}

func (o RunbookVersionOutput) ToRunbookVersionOutputWithContext(ctx context.Context) RunbookVersionOutput {
	return o
}

func (o RunbookVersionOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example:
// `{"foo-namespace.bar-key": "value"}`
func (o RunbookVersionOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Execution Workflow details.
func (o RunbookVersionOutput) ExecutionWorkflowDetails() RunbookVersionExecutionWorkflowDetailsOutput {
	return o.ApplyT(func(v *RunbookVersion) RunbookVersionExecutionWorkflowDetailsOutput {
		return v.ExecutionWorkflowDetails
	}).(RunbookVersionExecutionWorkflowDetailsOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists
// for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o RunbookVersionOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// (Updatable) The groups of the runbook.
func (o RunbookVersionOutput) Groups() RunbookVersionGroupArrayOutput {
	return o.ApplyT(func(v *RunbookVersion) RunbookVersionGroupArrayOutput { return v.Groups }).(RunbookVersionGroupArrayOutput)
}

func (o RunbookVersionOutput) IsLatest() pulumi.BoolOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.BoolOutput { return v.IsLatest }).(pulumi.BoolOutput)
}

// A message describing the current state in more detail. For example, can be used to provide
// actionable information for a resource in Failed state.
func (o RunbookVersionOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The name of the task
func (o RunbookVersionOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// (Updatable) Rollback Workflow details.
func (o RunbookVersionOutput) RollbackWorkflowDetails() RunbookVersionRollbackWorkflowDetailsOutput {
	return o.ApplyT(func(v *RunbookVersion) RunbookVersionRollbackWorkflowDetailsOutput { return v.RollbackWorkflowDetails }).(RunbookVersionRollbackWorkflowDetailsOutput)
}

// The OCID of the resource.
func (o RunbookVersionOutput) RunbookId() pulumi.StringOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.StringOutput { return v.RunbookId }).(pulumi.StringOutput)
}

// The current state of the FleetResource.
func (o RunbookVersionOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example:
// `{"orcl-cloud.free-tier-retained": "true"}`
func (o RunbookVersionOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// (Updatable) A set of tasks to execute in the runbook.
func (o RunbookVersionOutput) Tasks() RunbookVersionTaskArrayOutput {
	return o.ApplyT(func(v *RunbookVersion) RunbookVersionTaskArrayOutput { return v.Tasks }).(RunbookVersionTaskArrayOutput)
}

// The time this resource was created. An RFC3339 formatted datetime string.
func (o RunbookVersionOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time this resource was last updated. An RFC3339 formatted datetime string.
func (o RunbookVersionOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *RunbookVersion) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type RunbookVersionArrayOutput struct{ *pulumi.OutputState }

func (RunbookVersionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*RunbookVersion)(nil)).Elem()
}

func (o RunbookVersionArrayOutput) ToRunbookVersionArrayOutput() RunbookVersionArrayOutput {
	return o
}

func (o RunbookVersionArrayOutput) ToRunbookVersionArrayOutputWithContext(ctx context.Context) RunbookVersionArrayOutput {
	return o
}

func (o RunbookVersionArrayOutput) Index(i pulumi.IntInput) RunbookVersionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *RunbookVersion {
		return vs[0].([]*RunbookVersion)[vs[1].(int)]
	}).(RunbookVersionOutput)
}

type RunbookVersionMapOutput struct{ *pulumi.OutputState }

func (RunbookVersionMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*RunbookVersion)(nil)).Elem()
}

func (o RunbookVersionMapOutput) ToRunbookVersionMapOutput() RunbookVersionMapOutput {
	return o
}

func (o RunbookVersionMapOutput) ToRunbookVersionMapOutputWithContext(ctx context.Context) RunbookVersionMapOutput {
	return o
}

func (o RunbookVersionMapOutput) MapIndex(k pulumi.StringInput) RunbookVersionOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *RunbookVersion {
		return vs[0].(map[string]*RunbookVersion)[vs[1].(string)]
	}).(RunbookVersionOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*RunbookVersionInput)(nil)).Elem(), &RunbookVersion{})
	pulumi.RegisterInputType(reflect.TypeOf((*RunbookVersionArrayInput)(nil)).Elem(), RunbookVersionArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*RunbookVersionMapInput)(nil)).Elem(), RunbookVersionMap{})
	pulumi.RegisterOutputType(RunbookVersionOutput{})
	pulumi.RegisterOutputType(RunbookVersionArrayOutput{})
	pulumi.RegisterOutputType(RunbookVersionMapOutput{})
}
