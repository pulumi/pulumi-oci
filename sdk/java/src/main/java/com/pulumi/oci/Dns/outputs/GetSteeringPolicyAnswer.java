// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSteeringPolicyAnswer {
    /**
     * @return Set this property to `true` to indicate that the answer is administratively disabled, such as when the corresponding server is down for maintenance. An answer&#39;s `isDisabled` property can be referenced in `answerCondition` properties in rules using `answer.isDisabled`.
     * 
     */
    private final Boolean isDisabled;
    /**
     * @return A user-friendly name for the answer, unique within the steering policy. An answer&#39;s `name` property can be referenced in `answerCondition` properties of rules using `answer.name`.
     * 
     */
    private final String name;
    /**
     * @return The freeform name of a group of one or more records in which this record is included, such as &#34;LAX data center&#34;. An answer&#39;s `pool` property can be referenced in `answerCondition` properties of rules using `answer.pool`.
     * 
     */
    private final String pool;
    /**
     * @return The record&#39;s data, as whitespace-delimited tokens in type-specific presentation format. All RDATA is normalized and the returned presentation of your RDATA may differ from its initial input. For more information about RDATA, see [Supported DNS Resource Record Types](https://docs.cloud.oracle.com/iaas/Content/DNS/Reference/supporteddnsresource.htm).
     * 
     */
    private final String rdata;
    /**
     * @return The type of DNS record, such as A or CNAME. Only A, AAAA, and CNAME are supported. For more information, see [Supported DNS Resource Record Types](https://docs.cloud.oracle.com/iaas/Content/DNS/Reference/supporteddnsresource.htm).
     * 
     */
    private final String rtype;

    @CustomType.Constructor
    private GetSteeringPolicyAnswer(
        @CustomType.Parameter("isDisabled") Boolean isDisabled,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("pool") String pool,
        @CustomType.Parameter("rdata") String rdata,
        @CustomType.Parameter("rtype") String rtype) {
        this.isDisabled = isDisabled;
        this.name = name;
        this.pool = pool;
        this.rdata = rdata;
        this.rtype = rtype;
    }

    /**
     * @return Set this property to `true` to indicate that the answer is administratively disabled, such as when the corresponding server is down for maintenance. An answer&#39;s `isDisabled` property can be referenced in `answerCondition` properties in rules using `answer.isDisabled`.
     * 
     */
    public Boolean isDisabled() {
        return this.isDisabled;
    }
    /**
     * @return A user-friendly name for the answer, unique within the steering policy. An answer&#39;s `name` property can be referenced in `answerCondition` properties of rules using `answer.name`.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The freeform name of a group of one or more records in which this record is included, such as &#34;LAX data center&#34;. An answer&#39;s `pool` property can be referenced in `answerCondition` properties of rules using `answer.pool`.
     * 
     */
    public String pool() {
        return this.pool;
    }
    /**
     * @return The record&#39;s data, as whitespace-delimited tokens in type-specific presentation format. All RDATA is normalized and the returned presentation of your RDATA may differ from its initial input. For more information about RDATA, see [Supported DNS Resource Record Types](https://docs.cloud.oracle.com/iaas/Content/DNS/Reference/supporteddnsresource.htm).
     * 
     */
    public String rdata() {
        return this.rdata;
    }
    /**
     * @return The type of DNS record, such as A or CNAME. Only A, AAAA, and CNAME are supported. For more information, see [Supported DNS Resource Record Types](https://docs.cloud.oracle.com/iaas/Content/DNS/Reference/supporteddnsresource.htm).
     * 
     */
    public String rtype() {
        return this.rtype;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSteeringPolicyAnswer defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Boolean isDisabled;
        private String name;
        private String pool;
        private String rdata;
        private String rtype;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSteeringPolicyAnswer defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isDisabled = defaults.isDisabled;
    	      this.name = defaults.name;
    	      this.pool = defaults.pool;
    	      this.rdata = defaults.rdata;
    	      this.rtype = defaults.rtype;
        }

        public Builder isDisabled(Boolean isDisabled) {
            this.isDisabled = Objects.requireNonNull(isDisabled);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder pool(String pool) {
            this.pool = Objects.requireNonNull(pool);
            return this;
        }
        public Builder rdata(String rdata) {
            this.rdata = Objects.requireNonNull(rdata);
            return this;
        }
        public Builder rtype(String rtype) {
            this.rtype = Objects.requireNonNull(rtype);
            return this;
        }        public GetSteeringPolicyAnswer build() {
            return new GetSteeringPolicyAnswer(isDisabled, name, pool, rdata, rtype);
        }
    }
}
