// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Streaming.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Streaming.outputs.GetConnectHarnessesConnectHarness;
import com.pulumi.oci.Streaming.outputs.GetConnectHarnessesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetConnectHarnessesResult {
    /**
     * @return The OCID of the compartment that contains the connect harness.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of connect_harness.
     * 
     */
    private List<GetConnectHarnessesConnectHarness> connectHarnesses;
    private @Nullable List<GetConnectHarnessesFilter> filters;
    /**
     * @return The OCID of the connect harness.
     * 
     */
    private @Nullable String id;
    /**
     * @return The name of the connect harness. Avoid entering confidential information.  Example: `JDBCConnector`
     * 
     */
    private @Nullable String name;
    /**
     * @return The current state of the connect harness.
     * 
     */
    private @Nullable String state;

    private GetConnectHarnessesResult() {}
    /**
     * @return The OCID of the compartment that contains the connect harness.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of connect_harness.
     * 
     */
    public List<GetConnectHarnessesConnectHarness> connectHarnesses() {
        return this.connectHarnesses;
    }
    public List<GetConnectHarnessesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The OCID of the connect harness.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The name of the connect harness. Avoid entering confidential information.  Example: `JDBCConnector`
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The current state of the connect harness.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConnectHarnessesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetConnectHarnessesConnectHarness> connectHarnesses;
        private @Nullable List<GetConnectHarnessesFilter> filters;
        private @Nullable String id;
        private @Nullable String name;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetConnectHarnessesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectHarnesses = defaults.connectHarnesses;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder connectHarnesses(List<GetConnectHarnessesConnectHarness> connectHarnesses) {
            this.connectHarnesses = Objects.requireNonNull(connectHarnesses);
            return this;
        }
        public Builder connectHarnesses(GetConnectHarnessesConnectHarness... connectHarnesses) {
            return connectHarnesses(List.of(connectHarnesses));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetConnectHarnessesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetConnectHarnessesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetConnectHarnessesResult build() {
            final var o = new GetConnectHarnessesResult();
            o.compartmentId = compartmentId;
            o.connectHarnesses = connectHarnesses;
            o.filters = filters;
            o.id = id;
            o.name = name;
            o.state = state;
            return o;
        }
    }
}