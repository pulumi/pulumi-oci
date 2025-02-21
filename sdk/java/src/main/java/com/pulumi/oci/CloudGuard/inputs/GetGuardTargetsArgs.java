// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.inputs.GetGuardTargetsFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetGuardTargetsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetGuardTargetsArgs Empty = new GetGuardTargetsArgs();

    /**
     * Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
     * 
     */
    @Import(name="accessLevel")
    private @Nullable Output<String> accessLevel;

    /**
     * @return Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
     * 
     */
    public Optional<Output<String>> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }

    /**
     * The OCID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment in which to list resources.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the setting of `accessLevel`.
     * 
     */
    @Import(name="compartmentIdInSubtree")
    private @Nullable Output<Boolean> compartmentIdInSubtree;

    /**
     * @return Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the setting of `accessLevel`.
     * 
     */
    public Optional<Output<Boolean>> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetGuardTargetsFilterArgs>> filters;

    public Optional<Output<List<GetGuardTargetsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Default is false. When set to true, only the targets that would be deleted as part of security zone creation will be returned.
     * 
     */
    @Import(name="isNonSecurityZoneTargetsOnlyQuery")
    private @Nullable Output<Boolean> isNonSecurityZoneTargetsOnlyQuery;

    /**
     * @return Default is false. When set to true, only the targets that would be deleted as part of security zone creation will be returned.
     * 
     */
    public Optional<Output<Boolean>> isNonSecurityZoneTargetsOnlyQuery() {
        return Optional.ofNullable(this.isNonSecurityZoneTargetsOnlyQuery);
    }

    /**
     * The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetGuardTargetsArgs() {}

    private GetGuardTargetsArgs(GetGuardTargetsArgs $) {
        this.accessLevel = $.accessLevel;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.isNonSecurityZoneTargetsOnlyQuery = $.isNonSecurityZoneTargetsOnlyQuery;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetGuardTargetsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetGuardTargetsArgs $;

        public Builder() {
            $ = new GetGuardTargetsArgs();
        }

        public Builder(GetGuardTargetsArgs defaults) {
            $ = new GetGuardTargetsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param accessLevel Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
         * 
         * @return builder
         * 
         */
        public Builder accessLevel(@Nullable Output<String> accessLevel) {
            $.accessLevel = accessLevel;
            return this;
        }

        /**
         * @param accessLevel Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
         * 
         * @return builder
         * 
         */
        public Builder accessLevel(String accessLevel) {
            return accessLevel(Output.of(accessLevel));
        }

        /**
         * @param compartmentId The OCID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the setting of `accessLevel`.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(@Nullable Output<Boolean> compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the setting of `accessLevel`.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            return compartmentIdInSubtree(Output.of(compartmentIdInSubtree));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetGuardTargetsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetGuardTargetsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetGuardTargetsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isNonSecurityZoneTargetsOnlyQuery Default is false. When set to true, only the targets that would be deleted as part of security zone creation will be returned.
         * 
         * @return builder
         * 
         */
        public Builder isNonSecurityZoneTargetsOnlyQuery(@Nullable Output<Boolean> isNonSecurityZoneTargetsOnlyQuery) {
            $.isNonSecurityZoneTargetsOnlyQuery = isNonSecurityZoneTargetsOnlyQuery;
            return this;
        }

        /**
         * @param isNonSecurityZoneTargetsOnlyQuery Default is false. When set to true, only the targets that would be deleted as part of security zone creation will be returned.
         * 
         * @return builder
         * 
         */
        public Builder isNonSecurityZoneTargetsOnlyQuery(Boolean isNonSecurityZoneTargetsOnlyQuery) {
            return isNonSecurityZoneTargetsOnlyQuery(Output.of(isNonSecurityZoneTargetsOnlyQuery));
        }

        /**
         * @param state The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetGuardTargetsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetGuardTargetsArgs", "compartmentId");
            }
            return $;
        }
    }

}
