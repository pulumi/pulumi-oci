// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Functions.outputs.GetFunctionProvisionedConcurrencyConfig;
import com.pulumi.oci.Functions.outputs.GetFunctionTraceConfig;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetFunctionResult {
    /**
     * @return The OCID of the application the function belongs to.
     * 
     */
    private String applicationId;
    /**
     * @return The OCID of the compartment that contains the function.
     * 
     */
    private String compartmentId;
    /**
     * @return Function configuration. Overrides application configuration. Keys must be ASCII strings consisting solely of letters, digits, and the &#39;_&#39; (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{&#34;MY_FUNCTION_CONFIG&#34;: &#34;ConfVal&#34;}`
     * 
     */
    private Map<String,Object> config;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The display name of the function. The display name is unique within the application containing the function.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    private String functionId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the function.
     * 
     */
    private String id;
    /**
     * @return The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. Example: `phx.ocir.io/ten/functions/function:0.0.1`
     * 
     */
    private String image;
    /**
     * @return The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
     * 
     */
    private String imageDigest;
    /**
     * @return The base https invoke URL to set on a client in order to invoke a function. This URL will never change over the lifetime of the function and can be cached.
     * 
     */
    private String invokeEndpoint;
    /**
     * @return Maximum usable memory for the function (MiB).
     * 
     */
    private String memoryInMbs;
    /**
     * @return Define the strategy for provisioned concurrency for the function.
     * 
     */
    private List<GetFunctionProvisionedConcurrencyConfig> provisionedConcurrencyConfigs;
    /**
     * @return The current state of the function.
     * 
     */
    private String state;
    /**
     * @return The time the function was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The time the function was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    private String timeUpdated;
    /**
     * @return Timeout for executions of the function. Value in seconds.
     * 
     */
    private Integer timeoutInSeconds;
    /**
     * @return Define the tracing configuration for a function.
     * 
     */
    private List<GetFunctionTraceConfig> traceConfigs;

    private GetFunctionResult() {}
    /**
     * @return The OCID of the application the function belongs to.
     * 
     */
    public String applicationId() {
        return this.applicationId;
    }
    /**
     * @return The OCID of the compartment that contains the function.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Function configuration. Overrides application configuration. Keys must be ASCII strings consisting solely of letters, digits, and the &#39;_&#39; (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{&#34;MY_FUNCTION_CONFIG&#34;: &#34;ConfVal&#34;}`
     * 
     */
    public Map<String,Object> config() {
        return this.config;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The display name of the function. The display name is unique within the application containing the function.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    public String functionId() {
        return this.functionId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the function.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. Example: `phx.ocir.io/ten/functions/function:0.0.1`
     * 
     */
    public String image() {
        return this.image;
    }
    /**
     * @return The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
     * 
     */
    public String imageDigest() {
        return this.imageDigest;
    }
    /**
     * @return The base https invoke URL to set on a client in order to invoke a function. This URL will never change over the lifetime of the function and can be cached.
     * 
     */
    public String invokeEndpoint() {
        return this.invokeEndpoint;
    }
    /**
     * @return Maximum usable memory for the function (MiB).
     * 
     */
    public String memoryInMbs() {
        return this.memoryInMbs;
    }
    /**
     * @return Define the strategy for provisioned concurrency for the function.
     * 
     */
    public List<GetFunctionProvisionedConcurrencyConfig> provisionedConcurrencyConfigs() {
        return this.provisionedConcurrencyConfigs;
    }
    /**
     * @return The current state of the function.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The time the function was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the function was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return Timeout for executions of the function. Value in seconds.
     * 
     */
    public Integer timeoutInSeconds() {
        return this.timeoutInSeconds;
    }
    /**
     * @return Define the tracing configuration for a function.
     * 
     */
    public List<GetFunctionTraceConfig> traceConfigs() {
        return this.traceConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFunctionResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String applicationId;
        private String compartmentId;
        private Map<String,Object> config;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String functionId;
        private String id;
        private String image;
        private String imageDigest;
        private String invokeEndpoint;
        private String memoryInMbs;
        private List<GetFunctionProvisionedConcurrencyConfig> provisionedConcurrencyConfigs;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        private Integer timeoutInSeconds;
        private List<GetFunctionTraceConfig> traceConfigs;
        public Builder() {}
        public Builder(GetFunctionResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationId = defaults.applicationId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.config = defaults.config;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.functionId = defaults.functionId;
    	      this.id = defaults.id;
    	      this.image = defaults.image;
    	      this.imageDigest = defaults.imageDigest;
    	      this.invokeEndpoint = defaults.invokeEndpoint;
    	      this.memoryInMbs = defaults.memoryInMbs;
    	      this.provisionedConcurrencyConfigs = defaults.provisionedConcurrencyConfigs;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.timeoutInSeconds = defaults.timeoutInSeconds;
    	      this.traceConfigs = defaults.traceConfigs;
        }

        @CustomType.Setter
        public Builder applicationId(String applicationId) {
            this.applicationId = Objects.requireNonNull(applicationId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder config(Map<String,Object> config) {
            this.config = Objects.requireNonNull(config);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder functionId(String functionId) {
            this.functionId = Objects.requireNonNull(functionId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder image(String image) {
            this.image = Objects.requireNonNull(image);
            return this;
        }
        @CustomType.Setter
        public Builder imageDigest(String imageDigest) {
            this.imageDigest = Objects.requireNonNull(imageDigest);
            return this;
        }
        @CustomType.Setter
        public Builder invokeEndpoint(String invokeEndpoint) {
            this.invokeEndpoint = Objects.requireNonNull(invokeEndpoint);
            return this;
        }
        @CustomType.Setter
        public Builder memoryInMbs(String memoryInMbs) {
            this.memoryInMbs = Objects.requireNonNull(memoryInMbs);
            return this;
        }
        @CustomType.Setter
        public Builder provisionedConcurrencyConfigs(List<GetFunctionProvisionedConcurrencyConfig> provisionedConcurrencyConfigs) {
            this.provisionedConcurrencyConfigs = Objects.requireNonNull(provisionedConcurrencyConfigs);
            return this;
        }
        public Builder provisionedConcurrencyConfigs(GetFunctionProvisionedConcurrencyConfig... provisionedConcurrencyConfigs) {
            return provisionedConcurrencyConfigs(List.of(provisionedConcurrencyConfigs));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder timeoutInSeconds(Integer timeoutInSeconds) {
            this.timeoutInSeconds = Objects.requireNonNull(timeoutInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder traceConfigs(List<GetFunctionTraceConfig> traceConfigs) {
            this.traceConfigs = Objects.requireNonNull(traceConfigs);
            return this;
        }
        public Builder traceConfigs(GetFunctionTraceConfig... traceConfigs) {
            return traceConfigs(List.of(traceConfigs));
        }
        public GetFunctionResult build() {
            final var o = new GetFunctionResult();
            o.applicationId = applicationId;
            o.compartmentId = compartmentId;
            o.config = config;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.functionId = functionId;
            o.id = id;
            o.image = image;
            o.imageDigest = imageDigest;
            o.invokeEndpoint = invokeEndpoint;
            o.memoryInMbs = memoryInMbs;
            o.provisionedConcurrencyConfigs = provisionedConcurrencyConfigs;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.timeoutInSeconds = timeoutInSeconds;
            o.traceConfigs = traceConfigs;
            return o;
        }
    }
}