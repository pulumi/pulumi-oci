// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.AuditPolicyManagementAuditConditionArgs;
import com.pulumi.oci.DataSafe.inputs.AuditPolicyManagementAuditSpecificationArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AuditPolicyManagementState extends com.pulumi.resources.ResourceArgs {

    public static final AuditPolicyManagementState Empty = new AuditPolicyManagementState();

    /**
     * Required when provision_trigger is set. Lists the audit policy provisioning conditions for the target database.
     * 
     */
    @Import(name="auditConditions")
    private @Nullable Output<List<AuditPolicyManagementAuditConditionArgs>> auditConditions;

    /**
     * @return Required when provision_trigger is set. Lists the audit policy provisioning conditions for the target database.
     * 
     */
    public Optional<Output<List<AuditPolicyManagementAuditConditionArgs>>> auditConditions() {
        return Optional.ofNullable(this.auditConditions);
    }

    /**
     * Represents all available audit policy specifications relevant for the target database. For more details on available audit polcies, refer to [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827).
     * 
     */
    @Import(name="auditSpecifications")
    private @Nullable Output<List<AuditPolicyManagementAuditSpecificationArgs>> auditSpecifications;

    /**
     * @return Represents all available audit policy specifications relevant for the target database. For more details on available audit polcies, refer to [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827).
     * 
     */
    public Optional<Output<List<AuditPolicyManagementAuditSpecificationArgs>>> auditSpecifications() {
        return Optional.ofNullable(this.auditSpecifications);
    }

    /**
     * (Updatable) The OCID of the compartment containing the audit policy.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment containing the audit policy.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The description of the audit policy.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) The description of the audit policy.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) The display name of the audit policy. The name does not have to be unique, and it is changeable.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The display name of the audit policy. The name does not have to be unique, and it is changeable.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Option provided to users at the target to indicate whether the Data Safe service account has to be excluded while provisioning the audit policies.
     * 
     */
    @Import(name="isDataSafeServiceAccountExcluded")
    private @Nullable Output<Boolean> isDataSafeServiceAccountExcluded;

    /**
     * @return Option provided to users at the target to indicate whether the Data Safe service account has to be excluded while provisioning the audit policies.
     * 
     */
    public Optional<Output<Boolean>> isDataSafeServiceAccountExcluded() {
        return Optional.ofNullable(this.isDataSafeServiceAccountExcluded);
    }

    /**
     * Details about the current state of the audit policy in Data Safe.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return Details about the current state of the audit policy in Data Safe.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * (Updatable) An optional property when set to true triggers Provision.
     * 
     */
    @Import(name="provisionTrigger")
    private @Nullable Output<Boolean> provisionTrigger;

    /**
     * @return (Updatable) An optional property when set to true triggers Provision.
     * 
     */
    public Optional<Output<Boolean>> provisionTrigger() {
        return Optional.ofNullable(this.provisionTrigger);
    }

    /**
     * (Updatable) An optional property when set to true triggers Retrieve From Target.
     * 
     */
    @Import(name="retrieveFromTargetTrigger")
    private @Nullable Output<Boolean> retrieveFromTargetTrigger;

    /**
     * @return (Updatable) An optional property when set to true triggers Retrieve From Target.
     * 
     */
    public Optional<Output<Boolean>> retrieveFromTargetTrigger() {
        return Optional.ofNullable(this.retrieveFromTargetTrigger);
    }

    /**
     * The current state of the audit policy.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the audit policy.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The OCID of the target for which the audit policy is created.
     * 
     */
    @Import(name="targetId")
    private @Nullable Output<String> targetId;

    /**
     * @return The OCID of the target for which the audit policy is created.
     * 
     */
    public Optional<Output<String>> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    /**
     * The time the audit policy was created, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the audit policy was created, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * Indicates the last provisioning time of audit policies on the target, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeLastProvisioned")
    private @Nullable Output<String> timeLastProvisioned;

    /**
     * @return Indicates the last provisioning time of audit policies on the target, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeLastProvisioned() {
        return Optional.ofNullable(this.timeLastProvisioned);
    }

    /**
     * The time when the audit policies was last retrieved from this target, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeLastRetrieved")
    private @Nullable Output<String> timeLastRetrieved;

    /**
     * @return The time when the audit policies was last retrieved from this target, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeLastRetrieved() {
        return Optional.ofNullable(this.timeLastRetrieved);
    }

    /**
     * The last date and time the audit policy was updated, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The last date and time the audit policy was updated, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private AuditPolicyManagementState() {}

    private AuditPolicyManagementState(AuditPolicyManagementState $) {
        this.auditConditions = $.auditConditions;
        this.auditSpecifications = $.auditSpecifications;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isDataSafeServiceAccountExcluded = $.isDataSafeServiceAccountExcluded;
        this.lifecycleDetails = $.lifecycleDetails;
        this.provisionTrigger = $.provisionTrigger;
        this.retrieveFromTargetTrigger = $.retrieveFromTargetTrigger;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.targetId = $.targetId;
        this.timeCreated = $.timeCreated;
        this.timeLastProvisioned = $.timeLastProvisioned;
        this.timeLastRetrieved = $.timeLastRetrieved;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AuditPolicyManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AuditPolicyManagementState $;

        public Builder() {
            $ = new AuditPolicyManagementState();
        }

        public Builder(AuditPolicyManagementState defaults) {
            $ = new AuditPolicyManagementState(Objects.requireNonNull(defaults));
        }

        /**
         * @param auditConditions Required when provision_trigger is set. Lists the audit policy provisioning conditions for the target database.
         * 
         * @return builder
         * 
         */
        public Builder auditConditions(@Nullable Output<List<AuditPolicyManagementAuditConditionArgs>> auditConditions) {
            $.auditConditions = auditConditions;
            return this;
        }

        /**
         * @param auditConditions Required when provision_trigger is set. Lists the audit policy provisioning conditions for the target database.
         * 
         * @return builder
         * 
         */
        public Builder auditConditions(List<AuditPolicyManagementAuditConditionArgs> auditConditions) {
            return auditConditions(Output.of(auditConditions));
        }

        /**
         * @param auditConditions Required when provision_trigger is set. Lists the audit policy provisioning conditions for the target database.
         * 
         * @return builder
         * 
         */
        public Builder auditConditions(AuditPolicyManagementAuditConditionArgs... auditConditions) {
            return auditConditions(List.of(auditConditions));
        }

        /**
         * @param auditSpecifications Represents all available audit policy specifications relevant for the target database. For more details on available audit polcies, refer to [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827).
         * 
         * @return builder
         * 
         */
        public Builder auditSpecifications(@Nullable Output<List<AuditPolicyManagementAuditSpecificationArgs>> auditSpecifications) {
            $.auditSpecifications = auditSpecifications;
            return this;
        }

        /**
         * @param auditSpecifications Represents all available audit policy specifications relevant for the target database. For more details on available audit polcies, refer to [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827).
         * 
         * @return builder
         * 
         */
        public Builder auditSpecifications(List<AuditPolicyManagementAuditSpecificationArgs> auditSpecifications) {
            return auditSpecifications(Output.of(auditSpecifications));
        }

        /**
         * @param auditSpecifications Represents all available audit policy specifications relevant for the target database. For more details on available audit polcies, refer to [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827).
         * 
         * @return builder
         * 
         */
        public Builder auditSpecifications(AuditPolicyManagementAuditSpecificationArgs... auditSpecifications) {
            return auditSpecifications(List.of(auditSpecifications));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment containing the audit policy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment containing the audit policy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) The description of the audit policy.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) The description of the audit policy.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) The display name of the audit policy. The name does not have to be unique, and it is changeable.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The display name of the audit policy. The name does not have to be unique, and it is changeable.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isDataSafeServiceAccountExcluded Option provided to users at the target to indicate whether the Data Safe service account has to be excluded while provisioning the audit policies.
         * 
         * @return builder
         * 
         */
        public Builder isDataSafeServiceAccountExcluded(@Nullable Output<Boolean> isDataSafeServiceAccountExcluded) {
            $.isDataSafeServiceAccountExcluded = isDataSafeServiceAccountExcluded;
            return this;
        }

        /**
         * @param isDataSafeServiceAccountExcluded Option provided to users at the target to indicate whether the Data Safe service account has to be excluded while provisioning the audit policies.
         * 
         * @return builder
         * 
         */
        public Builder isDataSafeServiceAccountExcluded(Boolean isDataSafeServiceAccountExcluded) {
            return isDataSafeServiceAccountExcluded(Output.of(isDataSafeServiceAccountExcluded));
        }

        /**
         * @param lifecycleDetails Details about the current state of the audit policy in Data Safe.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails Details about the current state of the audit policy in Data Safe.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param provisionTrigger (Updatable) An optional property when set to true triggers Provision.
         * 
         * @return builder
         * 
         */
        public Builder provisionTrigger(@Nullable Output<Boolean> provisionTrigger) {
            $.provisionTrigger = provisionTrigger;
            return this;
        }

        /**
         * @param provisionTrigger (Updatable) An optional property when set to true triggers Provision.
         * 
         * @return builder
         * 
         */
        public Builder provisionTrigger(Boolean provisionTrigger) {
            return provisionTrigger(Output.of(provisionTrigger));
        }

        /**
         * @param retrieveFromTargetTrigger (Updatable) An optional property when set to true triggers Retrieve From Target.
         * 
         * @return builder
         * 
         */
        public Builder retrieveFromTargetTrigger(@Nullable Output<Boolean> retrieveFromTargetTrigger) {
            $.retrieveFromTargetTrigger = retrieveFromTargetTrigger;
            return this;
        }

        /**
         * @param retrieveFromTargetTrigger (Updatable) An optional property when set to true triggers Retrieve From Target.
         * 
         * @return builder
         * 
         */
        public Builder retrieveFromTargetTrigger(Boolean retrieveFromTargetTrigger) {
            return retrieveFromTargetTrigger(Output.of(retrieveFromTargetTrigger));
        }

        /**
         * @param state The current state of the audit policy.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the audit policy.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param targetId The OCID of the target for which the audit policy is created.
         * 
         * @return builder
         * 
         */
        public Builder targetId(@Nullable Output<String> targetId) {
            $.targetId = targetId;
            return this;
        }

        /**
         * @param targetId The OCID of the target for which the audit policy is created.
         * 
         * @return builder
         * 
         */
        public Builder targetId(String targetId) {
            return targetId(Output.of(targetId));
        }

        /**
         * @param timeCreated The time the audit policy was created, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the audit policy was created, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeLastProvisioned Indicates the last provisioning time of audit policies on the target, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeLastProvisioned(@Nullable Output<String> timeLastProvisioned) {
            $.timeLastProvisioned = timeLastProvisioned;
            return this;
        }

        /**
         * @param timeLastProvisioned Indicates the last provisioning time of audit policies on the target, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeLastProvisioned(String timeLastProvisioned) {
            return timeLastProvisioned(Output.of(timeLastProvisioned));
        }

        /**
         * @param timeLastRetrieved The time when the audit policies was last retrieved from this target, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeLastRetrieved(@Nullable Output<String> timeLastRetrieved) {
            $.timeLastRetrieved = timeLastRetrieved;
            return this;
        }

        /**
         * @param timeLastRetrieved The time when the audit policies was last retrieved from this target, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeLastRetrieved(String timeLastRetrieved) {
            return timeLastRetrieved(Output.of(timeLastRetrieved));
        }

        /**
         * @param timeUpdated The last date and time the audit policy was updated, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The last date and time the audit policy was updated, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public AuditPolicyManagementState build() {
            return $;
        }
    }

}
