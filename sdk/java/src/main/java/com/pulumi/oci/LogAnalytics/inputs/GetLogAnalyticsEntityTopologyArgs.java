// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetLogAnalyticsEntityTopologyArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetLogAnalyticsEntityTopologyArgs Empty = new GetLogAnalyticsEntityTopologyArgs();

    /**
     * The log analytics entity OCID.
     * 
     */
    @Import(name="logAnalyticsEntityId", required=true)
    private Output<String> logAnalyticsEntityId;

    /**
     * @return The log analytics entity OCID.
     * 
     */
    public Output<String> logAnalyticsEntityId() {
        return this.logAnalyticsEntityId;
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
     * A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetLogAnalyticsEntityTopologyArgs() {}

    private GetLogAnalyticsEntityTopologyArgs(GetLogAnalyticsEntityTopologyArgs $) {
        this.logAnalyticsEntityId = $.logAnalyticsEntityId;
        this.namespace = $.namespace;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetLogAnalyticsEntityTopologyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetLogAnalyticsEntityTopologyArgs $;

        public Builder() {
            $ = new GetLogAnalyticsEntityTopologyArgs();
        }

        public Builder(GetLogAnalyticsEntityTopologyArgs defaults) {
            $ = new GetLogAnalyticsEntityTopologyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param logAnalyticsEntityId The log analytics entity OCID.
         * 
         * @return builder
         * 
         */
        public Builder logAnalyticsEntityId(Output<String> logAnalyticsEntityId) {
            $.logAnalyticsEntityId = logAnalyticsEntityId;
            return this;
        }

        /**
         * @param logAnalyticsEntityId The log analytics entity OCID.
         * 
         * @return builder
         * 
         */
        public Builder logAnalyticsEntityId(String logAnalyticsEntityId) {
            return logAnalyticsEntityId(Output.of(logAnalyticsEntityId));
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
         * @param state A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetLogAnalyticsEntityTopologyArgs build() {
            $.logAnalyticsEntityId = Objects.requireNonNull($.logAnalyticsEntityId, "expected parameter 'logAnalyticsEntityId' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            return $;
        }
    }

}