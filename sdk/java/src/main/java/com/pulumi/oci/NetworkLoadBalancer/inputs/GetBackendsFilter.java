// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBackendsFilter extends com.pulumi.resources.InvokeArgs {

    public static final GetBackendsFilter Empty = new GetBackendsFilter();

    /**
     * A read-only field showing the IP address/IP OCID and port that uniquely identify this backend server in the backend set.  Example: `10.0.0.3:8080`, or `ocid1.privateip..oc1.&lt;var&gt;&amp;lt;unique_ID&amp;gt;&lt;/var&gt;:443` or `10.0.0.3:0`
     * 
     */
    @Import(name="name", required=true)
    private String name;

    /**
     * @return A read-only field showing the IP address/IP OCID and port that uniquely identify this backend server in the backend set.  Example: `10.0.0.3:8080`, or `ocid1.privateip..oc1.&lt;var&gt;&amp;lt;unique_ID&amp;gt;&lt;/var&gt;:443` or `10.0.0.3:0`
     * 
     */
    public String name() {
        return this.name;
    }

    @Import(name="regex")
    private @Nullable Boolean regex;

    public Optional<Boolean> regex() {
        return Optional.ofNullable(this.regex);
    }

    @Import(name="values", required=true)
    private List<String> values;

    public List<String> values() {
        return this.values;
    }

    private GetBackendsFilter() {}

    private GetBackendsFilter(GetBackendsFilter $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBackendsFilter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBackendsFilter $;

        public Builder() {
            $ = new GetBackendsFilter();
        }

        public Builder(GetBackendsFilter defaults) {
            $ = new GetBackendsFilter(Objects.requireNonNull(defaults));
        }

        /**
         * @param name A read-only field showing the IP address/IP OCID and port that uniquely identify this backend server in the backend set.  Example: `10.0.0.3:8080`, or `ocid1.privateip..oc1.&lt;var&gt;&amp;lt;unique_ID&amp;gt;&lt;/var&gt;:443` or `10.0.0.3:0`
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            $.name = name;
            return this;
        }

        public Builder regex(@Nullable Boolean regex) {
            $.regex = regex;
            return this;
        }

        public Builder values(List<String> values) {
            $.values = values;
            return this;
        }

        public Builder values(String... values) {
            return values(List.of(values));
        }

        public GetBackendsFilter build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            $.values = Objects.requireNonNull($.values, "expected parameter 'values' to be non-null");
            return $;
        }
    }

}