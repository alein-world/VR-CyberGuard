import { useLocation, Link } from "react-router-dom";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield } from "lucide-react";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error(
      "404 Error: User attempted to access non-existent route:",
      location.pathname
    );
  }, [location.pathname]);

  return (
    <div className="min-h-screen flex items-center justify-center cyber-grid">
      <div className="text-center">
        <div className="text-8xl mb-6">🚫</div>
        <h1 className="font-orbitron text-4xl font-bold mb-4 matrix-text">
          404 - Access Denied
        </h1>
        <p className="text-xl text-muted-foreground mb-8">
          The requested cyber resource could not be located in our secure network.
        </p>
        <Link to="/">
          <Button variant="cyber" size="lg">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Return to Cyber Arsenal
          </Button>
        </Link>
      </div>
    </div>
  );
};

export default NotFound;
