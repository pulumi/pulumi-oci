// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.VnMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPathAnalyzerTestProtocolParameter {
    /**
     * @return The destination port to use in a `PathAnalyzerTest` resource.
     * 
     */
    private Integer destinationPort;
    /**
     * @return The [ICMP](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) code.
     * 
     */
    private Integer icmpCode;
    /**
     * @return The [ICMP](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) type.
     * 
     */
    private Integer icmpType;
    /**
     * @return The source port to use in a `PathAnalyzerTest` resource.
     * 
     */
    private Integer sourcePort;
    /**
     * @return The type of the `Endpoint`.
     * 
     */
    private String type;

    private GetPathAnalyzerTestProtocolParameter() {}
    /**
     * @return The destination port to use in a `PathAnalyzerTest` resource.
     * 
     */
    public Integer destinationPort() {
        return this.destinationPort;
    }
    /**
     * @return The [ICMP](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) code.
     * 
     */
    public Integer icmpCode() {
        return this.icmpCode;
    }
    /**
     * @return The [ICMP](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) type.
     * 
     */
    public Integer icmpType() {
        return this.icmpType;
    }
    /**
     * @return The source port to use in a `PathAnalyzerTest` resource.
     * 
     */
    public Integer sourcePort() {
        return this.sourcePort;
    }
    /**
     * @return The type of the `Endpoint`.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPathAnalyzerTestProtocolParameter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer destinationPort;
        private Integer icmpCode;
        private Integer icmpType;
        private Integer sourcePort;
        private String type;
        public Builder() {}
        public Builder(GetPathAnalyzerTestProtocolParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.destinationPort = defaults.destinationPort;
    	      this.icmpCode = defaults.icmpCode;
    	      this.icmpType = defaults.icmpType;
    	      this.sourcePort = defaults.sourcePort;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder destinationPort(Integer destinationPort) {
            this.destinationPort = Objects.requireNonNull(destinationPort);
            return this;
        }
        @CustomType.Setter
        public Builder icmpCode(Integer icmpCode) {
            this.icmpCode = Objects.requireNonNull(icmpCode);
            return this;
        }
        @CustomType.Setter
        public Builder icmpType(Integer icmpType) {
            this.icmpType = Objects.requireNonNull(icmpType);
            return this;
        }
        @CustomType.Setter
        public Builder sourcePort(Integer sourcePort) {
            this.sourcePort = Objects.requireNonNull(sourcePort);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetPathAnalyzerTestProtocolParameter build() {
            final var o = new GetPathAnalyzerTestProtocolParameter();
            o.destinationPort = destinationPort;
            o.icmpCode = icmpCode;
            o.icmpType = icmpType;
            o.sourcePort = sourcePort;
            o.type = type;
            return o;
        }
    }
}