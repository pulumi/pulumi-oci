// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.GetMaskingPoliciesMaskingColumnsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMaskingPoliciesMaskingColumnsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMaskingPoliciesMaskingColumnsPlainArgs Empty = new GetMaskingPoliciesMaskingColumnsPlainArgs();

    /**
     * A filter to return only a specific column based on column name.
     * 
     */
    @Import(name="columnNames")
    private @Nullable List<String> columnNames;

    /**
     * @return A filter to return only a specific column based on column name.
     * 
     */
    public Optional<List<String>> columnNames() {
        return Optional.ofNullable(this.columnNames);
    }

    /**
     * A filter to return only resources that match the specified data types.
     * 
     */
    @Import(name="dataTypes")
    private @Nullable List<String> dataTypes;

    /**
     * @return A filter to return only resources that match the specified data types.
     * 
     */
    public Optional<List<String>> dataTypes() {
        return Optional.ofNullable(this.dataTypes);
    }

    @Import(name="filters")
    private @Nullable List<GetMaskingPoliciesMaskingColumnsFilter> filters;

    public Optional<List<GetMaskingPoliciesMaskingColumnsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return the masking column resources based on the value of their isMaskingEnabled attribute. A value of true returns only those columns for which masking is enabled. A value of false returns only those columns for which masking is disabled. Omitting this parameter returns all the masking columns in a masking policy.
     * 
     */
    @Import(name="isMaskingEnabled")
    private @Nullable Boolean isMaskingEnabled;

    /**
     * @return A filter to return the masking column resources based on the value of their isMaskingEnabled attribute. A value of true returns only those columns for which masking is enabled. A value of false returns only those columns for which masking is disabled. Omitting this parameter returns all the masking columns in a masking policy.
     * 
     */
    public Optional<Boolean> isMaskingEnabled() {
        return Optional.ofNullable(this.isMaskingEnabled);
    }

    /**
     * A filter to return masking columns based on whether the assigned masking formats need a seed value for masking. A value of true returns those masking columns that are using  Deterministic Encryption or Deterministic Substitution masking format.
     * 
     */
    @Import(name="isSeedRequired")
    private @Nullable Boolean isSeedRequired;

    /**
     * @return A filter to return masking columns based on whether the assigned masking formats need a seed value for masking. A value of true returns those masking columns that are using  Deterministic Encryption or Deterministic Substitution masking format.
     * 
     */
    public Optional<Boolean> isSeedRequired() {
        return Optional.ofNullable(this.isSeedRequired);
    }

    /**
     * A filter to return only the resources that match the specified masking column group.
     * 
     */
    @Import(name="maskingColumnGroups")
    private @Nullable List<String> maskingColumnGroups;

    /**
     * @return A filter to return only the resources that match the specified masking column group.
     * 
     */
    public Optional<List<String>> maskingColumnGroups() {
        return Optional.ofNullable(this.maskingColumnGroups);
    }

    /**
     * A filter to return only the resources that match the specified lifecycle states.
     * 
     */
    @Import(name="maskingColumnLifecycleState")
    private @Nullable String maskingColumnLifecycleState;

    /**
     * @return A filter to return only the resources that match the specified lifecycle states.
     * 
     */
    public Optional<String> maskingColumnLifecycleState() {
        return Optional.ofNullable(this.maskingColumnLifecycleState);
    }

    /**
     * The OCID of the masking policy.
     * 
     */
    @Import(name="maskingPolicyId", required=true)
    private String maskingPolicyId;

    /**
     * @return The OCID of the masking policy.
     * 
     */
    public String maskingPolicyId() {
        return this.maskingPolicyId;
    }

    /**
     * A filter to return only items related to a specific object type.
     * 
     */
    @Import(name="objectTypes")
    private @Nullable List<String> objectTypes;

    /**
     * @return A filter to return only items related to a specific object type.
     * 
     */
    public Optional<List<String>> objectTypes() {
        return Optional.ofNullable(this.objectTypes);
    }

    /**
     * A filter to return only items related to a specific object name.
     * 
     */
    @Import(name="objects")
    private @Nullable List<String> objects;

    /**
     * @return A filter to return only items related to a specific object name.
     * 
     */
    public Optional<List<String>> objects() {
        return Optional.ofNullable(this.objects);
    }

    /**
     * A filter to return only items related to specific schema name.
     * 
     */
    @Import(name="schemaNames")
    private @Nullable List<String> schemaNames;

    /**
     * @return A filter to return only items related to specific schema name.
     * 
     */
    public Optional<List<String>> schemaNames() {
        return Optional.ofNullable(this.schemaNames);
    }

    /**
     * A filter to return only items related to a specific sensitive type OCID.
     * 
     */
    @Import(name="sensitiveTypeId")
    private @Nullable String sensitiveTypeId;

    /**
     * @return A filter to return only items related to a specific sensitive type OCID.
     * 
     */
    public Optional<String> sensitiveTypeId() {
        return Optional.ofNullable(this.sensitiveTypeId);
    }

    /**
     * A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
     * 
     */
    @Import(name="timeCreatedGreaterThanOrEqualTo")
    private @Nullable String timeCreatedGreaterThanOrEqualTo;

    /**
     * @return A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
     * 
     */
    public Optional<String> timeCreatedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeCreatedGreaterThanOrEqualTo);
    }

    /**
     * Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Import(name="timeCreatedLessThan")
    private @Nullable String timeCreatedLessThan;

    /**
     * @return Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Optional<String> timeCreatedLessThan() {
        return Optional.ofNullable(this.timeCreatedLessThan);
    }

    /**
     * Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Import(name="timeUpdatedGreaterThanOrEqualTo")
    private @Nullable String timeUpdatedGreaterThanOrEqualTo;

    /**
     * @return Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Optional<String> timeUpdatedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeUpdatedGreaterThanOrEqualTo);
    }

    /**
     * Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Import(name="timeUpdatedLessThan")
    private @Nullable String timeUpdatedLessThan;

    /**
     * @return Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Optional<String> timeUpdatedLessThan() {
        return Optional.ofNullable(this.timeUpdatedLessThan);
    }

    private GetMaskingPoliciesMaskingColumnsPlainArgs() {}

    private GetMaskingPoliciesMaskingColumnsPlainArgs(GetMaskingPoliciesMaskingColumnsPlainArgs $) {
        this.columnNames = $.columnNames;
        this.dataTypes = $.dataTypes;
        this.filters = $.filters;
        this.isMaskingEnabled = $.isMaskingEnabled;
        this.isSeedRequired = $.isSeedRequired;
        this.maskingColumnGroups = $.maskingColumnGroups;
        this.maskingColumnLifecycleState = $.maskingColumnLifecycleState;
        this.maskingPolicyId = $.maskingPolicyId;
        this.objectTypes = $.objectTypes;
        this.objects = $.objects;
        this.schemaNames = $.schemaNames;
        this.sensitiveTypeId = $.sensitiveTypeId;
        this.timeCreatedGreaterThanOrEqualTo = $.timeCreatedGreaterThanOrEqualTo;
        this.timeCreatedLessThan = $.timeCreatedLessThan;
        this.timeUpdatedGreaterThanOrEqualTo = $.timeUpdatedGreaterThanOrEqualTo;
        this.timeUpdatedLessThan = $.timeUpdatedLessThan;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMaskingPoliciesMaskingColumnsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMaskingPoliciesMaskingColumnsPlainArgs $;

        public Builder() {
            $ = new GetMaskingPoliciesMaskingColumnsPlainArgs();
        }

        public Builder(GetMaskingPoliciesMaskingColumnsPlainArgs defaults) {
            $ = new GetMaskingPoliciesMaskingColumnsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param columnNames A filter to return only a specific column based on column name.
         * 
         * @return builder
         * 
         */
        public Builder columnNames(@Nullable List<String> columnNames) {
            $.columnNames = columnNames;
            return this;
        }

        /**
         * @param columnNames A filter to return only a specific column based on column name.
         * 
         * @return builder
         * 
         */
        public Builder columnNames(String... columnNames) {
            return columnNames(List.of(columnNames));
        }

        /**
         * @param dataTypes A filter to return only resources that match the specified data types.
         * 
         * @return builder
         * 
         */
        public Builder dataTypes(@Nullable List<String> dataTypes) {
            $.dataTypes = dataTypes;
            return this;
        }

        /**
         * @param dataTypes A filter to return only resources that match the specified data types.
         * 
         * @return builder
         * 
         */
        public Builder dataTypes(String... dataTypes) {
            return dataTypes(List.of(dataTypes));
        }

        public Builder filters(@Nullable List<GetMaskingPoliciesMaskingColumnsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetMaskingPoliciesMaskingColumnsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isMaskingEnabled A filter to return the masking column resources based on the value of their isMaskingEnabled attribute. A value of true returns only those columns for which masking is enabled. A value of false returns only those columns for which masking is disabled. Omitting this parameter returns all the masking columns in a masking policy.
         * 
         * @return builder
         * 
         */
        public Builder isMaskingEnabled(@Nullable Boolean isMaskingEnabled) {
            $.isMaskingEnabled = isMaskingEnabled;
            return this;
        }

        /**
         * @param isSeedRequired A filter to return masking columns based on whether the assigned masking formats need a seed value for masking. A value of true returns those masking columns that are using  Deterministic Encryption or Deterministic Substitution masking format.
         * 
         * @return builder
         * 
         */
        public Builder isSeedRequired(@Nullable Boolean isSeedRequired) {
            $.isSeedRequired = isSeedRequired;
            return this;
        }

        /**
         * @param maskingColumnGroups A filter to return only the resources that match the specified masking column group.
         * 
         * @return builder
         * 
         */
        public Builder maskingColumnGroups(@Nullable List<String> maskingColumnGroups) {
            $.maskingColumnGroups = maskingColumnGroups;
            return this;
        }

        /**
         * @param maskingColumnGroups A filter to return only the resources that match the specified masking column group.
         * 
         * @return builder
         * 
         */
        public Builder maskingColumnGroups(String... maskingColumnGroups) {
            return maskingColumnGroups(List.of(maskingColumnGroups));
        }

        /**
         * @param maskingColumnLifecycleState A filter to return only the resources that match the specified lifecycle states.
         * 
         * @return builder
         * 
         */
        public Builder maskingColumnLifecycleState(@Nullable String maskingColumnLifecycleState) {
            $.maskingColumnLifecycleState = maskingColumnLifecycleState;
            return this;
        }

        /**
         * @param maskingPolicyId The OCID of the masking policy.
         * 
         * @return builder
         * 
         */
        public Builder maskingPolicyId(String maskingPolicyId) {
            $.maskingPolicyId = maskingPolicyId;
            return this;
        }

        /**
         * @param objectTypes A filter to return only items related to a specific object type.
         * 
         * @return builder
         * 
         */
        public Builder objectTypes(@Nullable List<String> objectTypes) {
            $.objectTypes = objectTypes;
            return this;
        }

        /**
         * @param objectTypes A filter to return only items related to a specific object type.
         * 
         * @return builder
         * 
         */
        public Builder objectTypes(String... objectTypes) {
            return objectTypes(List.of(objectTypes));
        }

        /**
         * @param objects A filter to return only items related to a specific object name.
         * 
         * @return builder
         * 
         */
        public Builder objects(@Nullable List<String> objects) {
            $.objects = objects;
            return this;
        }

        /**
         * @param objects A filter to return only items related to a specific object name.
         * 
         * @return builder
         * 
         */
        public Builder objects(String... objects) {
            return objects(List.of(objects));
        }

        /**
         * @param schemaNames A filter to return only items related to specific schema name.
         * 
         * @return builder
         * 
         */
        public Builder schemaNames(@Nullable List<String> schemaNames) {
            $.schemaNames = schemaNames;
            return this;
        }

        /**
         * @param schemaNames A filter to return only items related to specific schema name.
         * 
         * @return builder
         * 
         */
        public Builder schemaNames(String... schemaNames) {
            return schemaNames(List.of(schemaNames));
        }

        /**
         * @param sensitiveTypeId A filter to return only items related to a specific sensitive type OCID.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveTypeId(@Nullable String sensitiveTypeId) {
            $.sensitiveTypeId = sensitiveTypeId;
            return this;
        }

        /**
         * @param timeCreatedGreaterThanOrEqualTo A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedGreaterThanOrEqualTo(@Nullable String timeCreatedGreaterThanOrEqualTo) {
            $.timeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeCreatedLessThan Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedLessThan(@Nullable String timeCreatedLessThan) {
            $.timeCreatedLessThan = timeCreatedLessThan;
            return this;
        }

        /**
         * @param timeUpdatedGreaterThanOrEqualTo Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdatedGreaterThanOrEqualTo(@Nullable String timeUpdatedGreaterThanOrEqualTo) {
            $.timeUpdatedGreaterThanOrEqualTo = timeUpdatedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeUpdatedLessThan Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdatedLessThan(@Nullable String timeUpdatedLessThan) {
            $.timeUpdatedLessThan = timeUpdatedLessThan;
            return this;
        }

        public GetMaskingPoliciesMaskingColumnsPlainArgs build() {
            $.maskingPolicyId = Objects.requireNonNull($.maskingPolicyId, "expected parameter 'maskingPolicyId' to be non-null");
            return $;
        }
    }

}