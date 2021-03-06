// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeployStagesDeployStageCollectionItemBlueGreenStrategy {
    /**
     * @return Name of the Ingress resource.
     * 
     */
    private final String ingressName;
    /**
     * @return First Namespace for deployment.
     * 
     */
    private final String namespaceA;
    /**
     * @return Second Namespace for deployment.
     * 
     */
    private final String namespaceB;
    /**
     * @return Canary strategy type
     * 
     */
    private final String strategyType;

    @CustomType.Constructor
    private GetDeployStagesDeployStageCollectionItemBlueGreenStrategy(
        @CustomType.Parameter("ingressName") String ingressName,
        @CustomType.Parameter("namespaceA") String namespaceA,
        @CustomType.Parameter("namespaceB") String namespaceB,
        @CustomType.Parameter("strategyType") String strategyType) {
        this.ingressName = ingressName;
        this.namespaceA = namespaceA;
        this.namespaceB = namespaceB;
        this.strategyType = strategyType;
    }

    /**
     * @return Name of the Ingress resource.
     * 
     */
    public String ingressName() {
        return this.ingressName;
    }
    /**
     * @return First Namespace for deployment.
     * 
     */
    public String namespaceA() {
        return this.namespaceA;
    }
    /**
     * @return Second Namespace for deployment.
     * 
     */
    public String namespaceB() {
        return this.namespaceB;
    }
    /**
     * @return Canary strategy type
     * 
     */
    public String strategyType() {
        return this.strategyType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployStagesDeployStageCollectionItemBlueGreenStrategy defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String ingressName;
        private String namespaceA;
        private String namespaceB;
        private String strategyType;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeployStagesDeployStageCollectionItemBlueGreenStrategy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ingressName = defaults.ingressName;
    	      this.namespaceA = defaults.namespaceA;
    	      this.namespaceB = defaults.namespaceB;
    	      this.strategyType = defaults.strategyType;
        }

        public Builder ingressName(String ingressName) {
            this.ingressName = Objects.requireNonNull(ingressName);
            return this;
        }
        public Builder namespaceA(String namespaceA) {
            this.namespaceA = Objects.requireNonNull(namespaceA);
            return this;
        }
        public Builder namespaceB(String namespaceB) {
            this.namespaceB = Objects.requireNonNull(namespaceB);
            return this;
        }
        public Builder strategyType(String strategyType) {
            this.strategyType = Objects.requireNonNull(strategyType);
            return this;
        }        public GetDeployStagesDeployStageCollectionItemBlueGreenStrategy build() {
            return new GetDeployStagesDeployStageCollectionItemBlueGreenStrategy(ingressName, namespaceA, namespaceB, strategyType);
        }
    }
}
