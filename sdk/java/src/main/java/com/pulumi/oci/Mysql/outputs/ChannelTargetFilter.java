// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class ChannelTargetFilter {
    /**
     * @return (Updatable) The type of the filter rule.
     * 
     */
    private String type;
    /**
     * @return (Updatable) The body of the filter rule. This can represent a database, a table, or a database pair (represented as &#34;db1-&gt;db2&#34;). For more information, see [Replication Filtering Rules](https://dev.mysql.com/doc/refman/8.0/en/replication-rules.html).
     * 
     */
    private String value;

    private ChannelTargetFilter() {}
    /**
     * @return (Updatable) The type of the filter rule.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return (Updatable) The body of the filter rule. This can represent a database, a table, or a database pair (represented as &#34;db1-&gt;db2&#34;). For more information, see [Replication Filtering Rules](https://dev.mysql.com/doc/refman/8.0/en/replication-rules.html).
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ChannelTargetFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String type;
        private String value;
        public Builder() {}
        public Builder(ChannelTargetFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public ChannelTargetFilter build() {
            final var o = new ChannelTargetFilter();
            o.type = type;
            o.value = value;
            return o;
        }
    }
}