// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.LogAnalytics.inputs.GetNamespaceRulesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetNamespaceRulesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNamespaceRulesArgs Empty = new GetNamespaceRulesArgs();

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
     * A filter to return rules whose displayName matches in whole or in part the specified value. The match is case-insensitive.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return rules whose displayName matches in whole or in part the specified value. The match is case-insensitive.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetNamespaceRulesFilterArgs>> filters;

    public Optional<Output<List<GetNamespaceRulesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The rule kind used for filtering. Only rules of the specified kind will be returned.
     * 
     */
    @Import(name="kind")
    private @Nullable Output<String> kind;

    /**
     * @return The rule kind used for filtering. Only rules of the specified kind will be returned.
     * 
     */
    public Optional<Output<String>> kind() {
        return Optional.ofNullable(this.kind);
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

    /**
     * The rule lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The rule lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetNamespaceRulesArgs() {}

    private GetNamespaceRulesArgs(GetNamespaceRulesArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.kind = $.kind;
        this.namespace = $.namespace;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNamespaceRulesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNamespaceRulesArgs $;

        public Builder() {
            $ = new GetNamespaceRulesArgs();
        }

        public Builder(GetNamespaceRulesArgs defaults) {
            $ = new GetNamespaceRulesArgs(Objects.requireNonNull(defaults));
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
         * @param displayName A filter to return rules whose displayName matches in whole or in part the specified value. The match is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return rules whose displayName matches in whole or in part the specified value. The match is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetNamespaceRulesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetNamespaceRulesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetNamespaceRulesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param kind The rule kind used for filtering. Only rules of the specified kind will be returned.
         * 
         * @return builder
         * 
         */
        public Builder kind(@Nullable Output<String> kind) {
            $.kind = kind;
            return this;
        }

        /**
         * @param kind The rule kind used for filtering. Only rules of the specified kind will be returned.
         * 
         * @return builder
         * 
         */
        public Builder kind(String kind) {
            return kind(Output.of(kind));
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

        /**
         * @param state The rule lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The rule lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetNamespaceRulesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            return $;
        }
    }

}