// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.GetAuditProfilesFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAuditProfilesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAuditProfilesArgs Empty = new GetAuditProfilesArgs();

    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     * 
     */
    @Import(name="accessLevel")
    private @Nullable Output<String> accessLevel;

    /**
     * @return Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     * 
     */
    public Optional<Output<String>> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }

    /**
     * A filter to return only items that have count of audit records collected greater than or equal to the specified value.
     * 
     */
    @Import(name="auditCollectedVolumeGreaterThanOrEqualTo")
    private @Nullable Output<String> auditCollectedVolumeGreaterThanOrEqualTo;

    /**
     * @return A filter to return only items that have count of audit records collected greater than or equal to the specified value.
     * 
     */
    public Optional<Output<String>> auditCollectedVolumeGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.auditCollectedVolumeGreaterThanOrEqualTo);
    }

    /**
     * A optional filter to return only resources that match the specified id.
     * 
     */
    @Import(name="auditProfileId")
    private @Nullable Output<String> auditProfileId;

    /**
     * @return A optional filter to return only resources that match the specified id.
     * 
     */
    public Optional<Output<String>> auditProfileId() {
        return Optional.ofNullable(this.auditProfileId);
    }

    /**
     * A filter to return only resources that match the specified compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    @Import(name="compartmentIdInSubtree")
    private @Nullable Output<Boolean> compartmentIdInSubtree;

    /**
     * @return Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    public Optional<Output<Boolean>> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }

    /**
     * A filter to return only resources that match the specified display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the specified display name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAuditProfilesFilterArgs>> filters;

    public Optional<Output<List<GetAuditProfilesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A optional filter to return only resources that match the specified retention configured value.
     * 
     */
    @Import(name="isOverrideGlobalRetentionSetting")
    private @Nullable Output<Boolean> isOverrideGlobalRetentionSetting;

    /**
     * @return A optional filter to return only resources that match the specified retention configured value.
     * 
     */
    public Optional<Output<Boolean>> isOverrideGlobalRetentionSetting() {
        return Optional.ofNullable(this.isOverrideGlobalRetentionSetting);
    }

    /**
     * Indicates if you want to continue audit record collection beyond the free limit of one million audit records per month per target database, incurring additional charges. The default value is inherited from the global settings. You can change at the global level or at the target level.
     * 
     */
    @Import(name="isPaidUsageEnabled")
    private @Nullable Output<Boolean> isPaidUsageEnabled;

    /**
     * @return Indicates if you want to continue audit record collection beyond the free limit of one million audit records per month per target database, incurring additional charges. The default value is inherited from the global settings. You can change at the global level or at the target level.
     * 
     */
    public Optional<Output<Boolean>> isPaidUsageEnabled() {
        return Optional.ofNullable(this.isPaidUsageEnabled);
    }

    /**
     * A optional filter to return only resources that match the specified lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A optional filter to return only resources that match the specified lifecycle state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only items related to a specific target OCID.
     * 
     */
    @Import(name="targetId")
    private @Nullable Output<String> targetId;

    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    public Optional<Output<String>> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    private GetAuditProfilesArgs() {}

    private GetAuditProfilesArgs(GetAuditProfilesArgs $) {
        this.accessLevel = $.accessLevel;
        this.auditCollectedVolumeGreaterThanOrEqualTo = $.auditCollectedVolumeGreaterThanOrEqualTo;
        this.auditProfileId = $.auditProfileId;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.isOverrideGlobalRetentionSetting = $.isOverrideGlobalRetentionSetting;
        this.isPaidUsageEnabled = $.isPaidUsageEnabled;
        this.state = $.state;
        this.targetId = $.targetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAuditProfilesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAuditProfilesArgs $;

        public Builder() {
            $ = new GetAuditProfilesArgs();
        }

        public Builder(GetAuditProfilesArgs defaults) {
            $ = new GetAuditProfilesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param accessLevel Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
         * 
         * @return builder
         * 
         */
        public Builder accessLevel(@Nullable Output<String> accessLevel) {
            $.accessLevel = accessLevel;
            return this;
        }

        /**
         * @param accessLevel Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
         * 
         * @return builder
         * 
         */
        public Builder accessLevel(String accessLevel) {
            return accessLevel(Output.of(accessLevel));
        }

        /**
         * @param auditCollectedVolumeGreaterThanOrEqualTo A filter to return only items that have count of audit records collected greater than or equal to the specified value.
         * 
         * @return builder
         * 
         */
        public Builder auditCollectedVolumeGreaterThanOrEqualTo(@Nullable Output<String> auditCollectedVolumeGreaterThanOrEqualTo) {
            $.auditCollectedVolumeGreaterThanOrEqualTo = auditCollectedVolumeGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param auditCollectedVolumeGreaterThanOrEqualTo A filter to return only items that have count of audit records collected greater than or equal to the specified value.
         * 
         * @return builder
         * 
         */
        public Builder auditCollectedVolumeGreaterThanOrEqualTo(String auditCollectedVolumeGreaterThanOrEqualTo) {
            return auditCollectedVolumeGreaterThanOrEqualTo(Output.of(auditCollectedVolumeGreaterThanOrEqualTo));
        }

        /**
         * @param auditProfileId A optional filter to return only resources that match the specified id.
         * 
         * @return builder
         * 
         */
        public Builder auditProfileId(@Nullable Output<String> auditProfileId) {
            $.auditProfileId = auditProfileId;
            return this;
        }

        /**
         * @param auditProfileId A optional filter to return only resources that match the specified id.
         * 
         * @return builder
         * 
         */
        public Builder auditProfileId(String auditProfileId) {
            return auditProfileId(Output.of(auditProfileId));
        }

        /**
         * @param compartmentId A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(@Nullable Output<Boolean> compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            return compartmentIdInSubtree(Output.of(compartmentIdInSubtree));
        }

        /**
         * @param displayName A filter to return only resources that match the specified display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the specified display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetAuditProfilesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAuditProfilesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAuditProfilesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isOverrideGlobalRetentionSetting A optional filter to return only resources that match the specified retention configured value.
         * 
         * @return builder
         * 
         */
        public Builder isOverrideGlobalRetentionSetting(@Nullable Output<Boolean> isOverrideGlobalRetentionSetting) {
            $.isOverrideGlobalRetentionSetting = isOverrideGlobalRetentionSetting;
            return this;
        }

        /**
         * @param isOverrideGlobalRetentionSetting A optional filter to return only resources that match the specified retention configured value.
         * 
         * @return builder
         * 
         */
        public Builder isOverrideGlobalRetentionSetting(Boolean isOverrideGlobalRetentionSetting) {
            return isOverrideGlobalRetentionSetting(Output.of(isOverrideGlobalRetentionSetting));
        }

        /**
         * @param isPaidUsageEnabled Indicates if you want to continue audit record collection beyond the free limit of one million audit records per month per target database, incurring additional charges. The default value is inherited from the global settings. You can change at the global level or at the target level.
         * 
         * @return builder
         * 
         */
        public Builder isPaidUsageEnabled(@Nullable Output<Boolean> isPaidUsageEnabled) {
            $.isPaidUsageEnabled = isPaidUsageEnabled;
            return this;
        }

        /**
         * @param isPaidUsageEnabled Indicates if you want to continue audit record collection beyond the free limit of one million audit records per month per target database, incurring additional charges. The default value is inherited from the global settings. You can change at the global level or at the target level.
         * 
         * @return builder
         * 
         */
        public Builder isPaidUsageEnabled(Boolean isPaidUsageEnabled) {
            return isPaidUsageEnabled(Output.of(isPaidUsageEnabled));
        }

        /**
         * @param state A optional filter to return only resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A optional filter to return only resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param targetId A filter to return only items related to a specific target OCID.
         * 
         * @return builder
         * 
         */
        public Builder targetId(@Nullable Output<String> targetId) {
            $.targetId = targetId;
            return this;
        }

        /**
         * @param targetId A filter to return only items related to a specific target OCID.
         * 
         * @return builder
         * 
         */
        public Builder targetId(String targetId) {
            return targetId(Output.of(targetId));
        }

        public GetAuditProfilesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}