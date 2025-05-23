// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opa;

import com.pulumi.core.Output;
import com.pulumi.core.TypeShape;
import com.pulumi.deployment.Deployment;
import com.pulumi.deployment.InvokeOptions;
import com.pulumi.deployment.InvokeOutputOptions;
import com.pulumi.oci.Opa.inputs.GetOpaInstanceArgs;
import com.pulumi.oci.Opa.inputs.GetOpaInstancePlainArgs;
import com.pulumi.oci.Opa.inputs.GetOpaInstancesArgs;
import com.pulumi.oci.Opa.inputs.GetOpaInstancesPlainArgs;
import com.pulumi.oci.Opa.outputs.GetOpaInstanceResult;
import com.pulumi.oci.Opa.outputs.GetOpaInstancesResult;
import com.pulumi.oci.Utilities;
import java.util.concurrent.CompletableFuture;

public final class OpaFunctions {
    /**
     * This data source provides details about a specific Opa Instance resource in Oracle Cloud Infrastructure Opa service.
     * 
     * Gets a OpaInstance by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstance = OpaFunctions.getOpaInstance(GetOpaInstanceArgs.builder()
     *             .opaInstanceId(testOpaInstanceOciOpaOpaInstance.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetOpaInstanceResult> getOpaInstance(GetOpaInstanceArgs args) {
        return getOpaInstance(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Opa Instance resource in Oracle Cloud Infrastructure Opa service.
     * 
     * Gets a OpaInstance by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstance = OpaFunctions.getOpaInstance(GetOpaInstanceArgs.builder()
     *             .opaInstanceId(testOpaInstanceOciOpaOpaInstance.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetOpaInstanceResult> getOpaInstancePlain(GetOpaInstancePlainArgs args) {
        return getOpaInstancePlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Opa Instance resource in Oracle Cloud Infrastructure Opa service.
     * 
     * Gets a OpaInstance by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstance = OpaFunctions.getOpaInstance(GetOpaInstanceArgs.builder()
     *             .opaInstanceId(testOpaInstanceOciOpaOpaInstance.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetOpaInstanceResult> getOpaInstance(GetOpaInstanceArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:Opa/getOpaInstance:getOpaInstance", TypeShape.of(GetOpaInstanceResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Opa Instance resource in Oracle Cloud Infrastructure Opa service.
     * 
     * Gets a OpaInstance by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstance = OpaFunctions.getOpaInstance(GetOpaInstanceArgs.builder()
     *             .opaInstanceId(testOpaInstanceOciOpaOpaInstance.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetOpaInstanceResult> getOpaInstance(GetOpaInstanceArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:Opa/getOpaInstance:getOpaInstance", TypeShape.of(GetOpaInstanceResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Opa Instance resource in Oracle Cloud Infrastructure Opa service.
     * 
     * Gets a OpaInstance by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstance = OpaFunctions.getOpaInstance(GetOpaInstanceArgs.builder()
     *             .opaInstanceId(testOpaInstanceOciOpaOpaInstance.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetOpaInstanceResult> getOpaInstancePlain(GetOpaInstancePlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:Opa/getOpaInstance:getOpaInstance", TypeShape.of(GetOpaInstanceResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Opa Instances in Oracle Cloud Infrastructure Opa service.
     * 
     * Returns a list of OpaInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstances = OpaFunctions.getOpaInstances(GetOpaInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .displayName(opaInstanceDisplayName)
     *             .id(opaInstanceId)
     *             .state(opaInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetOpaInstancesResult> getOpaInstances() {
        return getOpaInstances(GetOpaInstancesArgs.Empty, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Opa Instances in Oracle Cloud Infrastructure Opa service.
     * 
     * Returns a list of OpaInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstances = OpaFunctions.getOpaInstances(GetOpaInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .displayName(opaInstanceDisplayName)
     *             .id(opaInstanceId)
     *             .state(opaInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetOpaInstancesResult> getOpaInstancesPlain() {
        return getOpaInstancesPlain(GetOpaInstancesPlainArgs.Empty, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Opa Instances in Oracle Cloud Infrastructure Opa service.
     * 
     * Returns a list of OpaInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstances = OpaFunctions.getOpaInstances(GetOpaInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .displayName(opaInstanceDisplayName)
     *             .id(opaInstanceId)
     *             .state(opaInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetOpaInstancesResult> getOpaInstances(GetOpaInstancesArgs args) {
        return getOpaInstances(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Opa Instances in Oracle Cloud Infrastructure Opa service.
     * 
     * Returns a list of OpaInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstances = OpaFunctions.getOpaInstances(GetOpaInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .displayName(opaInstanceDisplayName)
     *             .id(opaInstanceId)
     *             .state(opaInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetOpaInstancesResult> getOpaInstancesPlain(GetOpaInstancesPlainArgs args) {
        return getOpaInstancesPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Opa Instances in Oracle Cloud Infrastructure Opa service.
     * 
     * Returns a list of OpaInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstances = OpaFunctions.getOpaInstances(GetOpaInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .displayName(opaInstanceDisplayName)
     *             .id(opaInstanceId)
     *             .state(opaInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetOpaInstancesResult> getOpaInstances(GetOpaInstancesArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:Opa/getOpaInstances:getOpaInstances", TypeShape.of(GetOpaInstancesResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Opa Instances in Oracle Cloud Infrastructure Opa service.
     * 
     * Returns a list of OpaInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstances = OpaFunctions.getOpaInstances(GetOpaInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .displayName(opaInstanceDisplayName)
     *             .id(opaInstanceId)
     *             .state(opaInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetOpaInstancesResult> getOpaInstances(GetOpaInstancesArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:Opa/getOpaInstances:getOpaInstances", TypeShape.of(GetOpaInstancesResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Opa Instances in Oracle Cloud Infrastructure Opa service.
     * 
     * Returns a list of OpaInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Opa.OpaFunctions;
     * import com.pulumi.oci.Opa.inputs.GetOpaInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testOpaInstances = OpaFunctions.getOpaInstances(GetOpaInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .displayName(opaInstanceDisplayName)
     *             .id(opaInstanceId)
     *             .state(opaInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetOpaInstancesResult> getOpaInstancesPlain(GetOpaInstancesPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:Opa/getOpaInstances:getOpaInstances", TypeShape.of(GetOpaInstancesResult.class), args, Utilities.withVersion(options));
    }
}
