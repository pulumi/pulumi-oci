// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetShapesShape {
    /**
     * @return The number of CPU Cores the Instance provides. These are &#34;OCPU&#34;s.
     * 
     */
    private Integer cpuCoreCount;
    /**
     * @return Return shapes that are supported by the service feature.
     * 
     */
    private List<String> isSupportedFors;
    /**
     * @return The amount of RAM the Instance provides. This is an IEC base-2 number.
     * 
     */
    private Integer memorySizeInGbs;
    /**
     * @return Name
     * 
     */
    private String name;

    private GetShapesShape() {}
    /**
     * @return The number of CPU Cores the Instance provides. These are &#34;OCPU&#34;s.
     * 
     */
    public Integer cpuCoreCount() {
        return this.cpuCoreCount;
    }
    /**
     * @return Return shapes that are supported by the service feature.
     * 
     */
    public List<String> isSupportedFors() {
        return this.isSupportedFors;
    }
    /**
     * @return The amount of RAM the Instance provides. This is an IEC base-2 number.
     * 
     */
    public Integer memorySizeInGbs() {
        return this.memorySizeInGbs;
    }
    /**
     * @return Name
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetShapesShape defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer cpuCoreCount;
        private List<String> isSupportedFors;
        private Integer memorySizeInGbs;
        private String name;
        public Builder() {}
        public Builder(GetShapesShape defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cpuCoreCount = defaults.cpuCoreCount;
    	      this.isSupportedFors = defaults.isSupportedFors;
    	      this.memorySizeInGbs = defaults.memorySizeInGbs;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder cpuCoreCount(Integer cpuCoreCount) {
            this.cpuCoreCount = Objects.requireNonNull(cpuCoreCount);
            return this;
        }
        @CustomType.Setter
        public Builder isSupportedFors(List<String> isSupportedFors) {
            this.isSupportedFors = Objects.requireNonNull(isSupportedFors);
            return this;
        }
        public Builder isSupportedFors(String... isSupportedFors) {
            return isSupportedFors(List.of(isSupportedFors));
        }
        @CustomType.Setter
        public Builder memorySizeInGbs(Integer memorySizeInGbs) {
            this.memorySizeInGbs = Objects.requireNonNull(memorySizeInGbs);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetShapesShape build() {
            final var o = new GetShapesShape();
            o.cpuCoreCount = cpuCoreCount;
            o.isSupportedFors = isSupportedFors;
            o.memorySizeInGbs = memorySizeInGbs;
            o.name = name;
            return o;
        }
    }
}