// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetLogAnalyticsEntityTopologyPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetLogAnalyticsEntityTopologyPlainArgs Empty = new GetLogAnalyticsEntityTopologyPlainArgs();

    /**
     * The log analytics entity OCID.
     * 
     */
    @Import(name="logAnalyticsEntityId", required=true)
    private String logAnalyticsEntityId;

    /**
     * @return The log analytics entity OCID.
     * 
     */
    public String logAnalyticsEntityId() {
        return this.logAnalyticsEntityId;
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private String namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public String namespace() {
        return this.namespace;
    }

    /**
     * A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetLogAnalyticsEntityTopologyPlainArgs() {}

    private GetLogAnalyticsEntityTopologyPlainArgs(GetLogAnalyticsEntityTopologyPlainArgs $) {
        this.logAnalyticsEntityId = $.logAnalyticsEntityId;
        this.namespace = $.namespace;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetLogAnalyticsEntityTopologyPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetLogAnalyticsEntityTopologyPlainArgs $;

        public Builder() {
            $ = new GetLogAnalyticsEntityTopologyPlainArgs();
        }

        public Builder(GetLogAnalyticsEntityTopologyPlainArgs defaults) {
            $ = new GetLogAnalyticsEntityTopologyPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param logAnalyticsEntityId The log analytics entity OCID.
         * 
         * @return builder
         * 
         */
        public Builder logAnalyticsEntityId(String logAnalyticsEntityId) {
            $.logAnalyticsEntityId = logAnalyticsEntityId;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param state A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetLogAnalyticsEntityTopologyPlainArgs build() {
            $.logAnalyticsEntityId = Objects.requireNonNull($.logAnalyticsEntityId, "expected parameter 'logAnalyticsEntityId' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            return $;
        }
    }

}
