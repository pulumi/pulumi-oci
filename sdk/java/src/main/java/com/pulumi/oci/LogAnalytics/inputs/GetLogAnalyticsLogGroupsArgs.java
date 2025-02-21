// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.inputs.GetLogAnalyticsLogGroupsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetLogAnalyticsLogGroupsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetLogAnalyticsLogGroupsArgs Empty = new GetLogAnalyticsLogGroupsArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only log analytics log groups whose displayName matches the entire display name given. The match is case-insensitive.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only log analytics log groups whose displayName matches the entire display name given. The match is case-insensitive.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetLogAnalyticsLogGroupsFilterArgs>> filters;

    public Optional<Output<List<GetLogAnalyticsLogGroupsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    private GetLogAnalyticsLogGroupsArgs() {}

    private GetLogAnalyticsLogGroupsArgs(GetLogAnalyticsLogGroupsArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetLogAnalyticsLogGroupsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetLogAnalyticsLogGroupsArgs $;

        public Builder() {
            $ = new GetLogAnalyticsLogGroupsArgs();
        }

        public Builder(GetLogAnalyticsLogGroupsArgs defaults) {
            $ = new GetLogAnalyticsLogGroupsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A filter to return only log analytics log groups whose displayName matches the entire display name given. The match is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only log analytics log groups whose displayName matches the entire display name given. The match is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetLogAnalyticsLogGroupsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetLogAnalyticsLogGroupsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetLogAnalyticsLogGroupsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public GetLogAnalyticsLogGroupsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetLogAnalyticsLogGroupsArgs", "compartmentId");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("GetLogAnalyticsLogGroupsArgs", "namespace");
            }
            return $;
        }
    }

}
