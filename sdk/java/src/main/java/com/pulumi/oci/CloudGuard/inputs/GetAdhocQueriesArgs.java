// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.inputs.GetAdhocQueriesFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAdhocQueriesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAdhocQueriesArgs Empty = new GetAdhocQueriesArgs();

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
     * The status of the adhoc query created. Default value for state is provisioning. If no value is specified state is provisioning.
     * 
     */
    @Import(name="adhocQueryStatus")
    private @Nullable Output<String> adhocQueryStatus;

    /**
     * @return The status of the adhoc query created. Default value for state is provisioning. If no value is specified state is provisioning.
     * 
     */
    public Optional<Output<String>> adhocQueryStatus() {
        return Optional.ofNullable(this.adhocQueryStatus);
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

    @Import(name="filters")
    private @Nullable Output<List<GetAdhocQueriesFilterArgs>> filters;

    public Optional<Output<List<GetAdhocQueriesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * End time for a filter. If end time is not specified, end time will be set to current time.
     * 
     */
    @Import(name="timeEndedFilterQueryParam")
    private @Nullable Output<String> timeEndedFilterQueryParam;

    /**
     * @return End time for a filter. If end time is not specified, end time will be set to current time.
     * 
     */
    public Optional<Output<String>> timeEndedFilterQueryParam() {
        return Optional.ofNullable(this.timeEndedFilterQueryParam);
    }

    /**
     * Start time for a filter. If start time is not specified, start time will be set to current time - 30 days.
     * 
     */
    @Import(name="timeStartedFilterQueryParam")
    private @Nullable Output<String> timeStartedFilterQueryParam;

    /**
     * @return Start time for a filter. If start time is not specified, start time will be set to current time - 30 days.
     * 
     */
    public Optional<Output<String>> timeStartedFilterQueryParam() {
        return Optional.ofNullable(this.timeStartedFilterQueryParam);
    }

    private GetAdhocQueriesArgs() {}

    private GetAdhocQueriesArgs(GetAdhocQueriesArgs $) {
        this.accessLevel = $.accessLevel;
        this.adhocQueryStatus = $.adhocQueryStatus;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.filters = $.filters;
        this.timeEndedFilterQueryParam = $.timeEndedFilterQueryParam;
        this.timeStartedFilterQueryParam = $.timeStartedFilterQueryParam;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAdhocQueriesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAdhocQueriesArgs $;

        public Builder() {
            $ = new GetAdhocQueriesArgs();
        }

        public Builder(GetAdhocQueriesArgs defaults) {
            $ = new GetAdhocQueriesArgs(Objects.requireNonNull(defaults));
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
         * @param adhocQueryStatus The status of the adhoc query created. Default value for state is provisioning. If no value is specified state is provisioning.
         * 
         * @return builder
         * 
         */
        public Builder adhocQueryStatus(@Nullable Output<String> adhocQueryStatus) {
            $.adhocQueryStatus = adhocQueryStatus;
            return this;
        }

        /**
         * @param adhocQueryStatus The status of the adhoc query created. Default value for state is provisioning. If no value is specified state is provisioning.
         * 
         * @return builder
         * 
         */
        public Builder adhocQueryStatus(String adhocQueryStatus) {
            return adhocQueryStatus(Output.of(adhocQueryStatus));
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

        public Builder filters(@Nullable Output<List<GetAdhocQueriesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAdhocQueriesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAdhocQueriesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param timeEndedFilterQueryParam End time for a filter. If end time is not specified, end time will be set to current time.
         * 
         * @return builder
         * 
         */
        public Builder timeEndedFilterQueryParam(@Nullable Output<String> timeEndedFilterQueryParam) {
            $.timeEndedFilterQueryParam = timeEndedFilterQueryParam;
            return this;
        }

        /**
         * @param timeEndedFilterQueryParam End time for a filter. If end time is not specified, end time will be set to current time.
         * 
         * @return builder
         * 
         */
        public Builder timeEndedFilterQueryParam(String timeEndedFilterQueryParam) {
            return timeEndedFilterQueryParam(Output.of(timeEndedFilterQueryParam));
        }

        /**
         * @param timeStartedFilterQueryParam Start time for a filter. If start time is not specified, start time will be set to current time - 30 days.
         * 
         * @return builder
         * 
         */
        public Builder timeStartedFilterQueryParam(@Nullable Output<String> timeStartedFilterQueryParam) {
            $.timeStartedFilterQueryParam = timeStartedFilterQueryParam;
            return this;
        }

        /**
         * @param timeStartedFilterQueryParam Start time for a filter. If start time is not specified, start time will be set to current time - 30 days.
         * 
         * @return builder
         * 
         */
        public Builder timeStartedFilterQueryParam(String timeStartedFilterQueryParam) {
            return timeStartedFilterQueryParam(Output.of(timeStartedFilterQueryParam));
        }

        public GetAdhocQueriesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetAdhocQueriesArgs", "compartmentId");
            }
            return $;
        }
    }

}
