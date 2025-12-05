<?php
session_start();
require_once 'config.php';

$conn = getDBConnection();
$success = false;
$error = '';

if (isset($_POST['register'])) {
    $nom = htmlspecialchars($_POST['nom']);
    $prenom = htmlspecialchars($_POST['prenom']);
    $email = htmlspecialchars($_POST['email']);
    $domaine = substr(strrchr($email, "@"), 1);
    if ($domaine !== SSO_DOMAIN) {
        $error = "Seuls les emails @" . SSO_DOMAIN . " sont autorisés !";
    } else {
        $check = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $check->bind_param("s", $email);
        $check->execute();
        $result = $check->get_result();
        
        if ($result->num_rows > 0) {
            $error = "Cet email est déjà enregistré !";
        } else {

    $id_unique = 'KOO-' . strtoupper(substr($prenom, 0 , 3)) . strtoupper(substr($nom, 1, 4 )) . '-' . rand(1000, 9999);
            $personal_token = 'tok_' . bin2hex(random_bytes(32));
    $insert = $conn->prepare("INSERT INTO users (email, nom, prenom, id_unique, personal_token) VALUES (?, ?, ?, ?, ?)");
            $insert->bind_param("sssss", $email, $nom, $prenom, $id_unique, $personal_token);
            
            if ($insert->execute()) {
                $success = true;
                $_SESSION['new_id'] = $id_unique;
                $_SESSION['new_token'] = $personal_token;
                $_SESSION['new_email'] = $email;
            } else {
                $error = "Erreur lors de l'inscription !";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Créer un compte - Seyrin</title>
</head>
<body>
    <div class="container">
        <h1>Créer un compte Seyrin Auth Systems</h1>
        
        <?php if ($success): ?>
            <div class="success-box">
                <h2>✅ Compte créé avec succès !</h2>
                <p style="margin-bottom: 15px;">Conservez précieusement ces informations :</p>
                
                <div class="credential">
                    <strong>Email :</strong><br>
                    <?php echo htmlspecialchars($_SESSION['new_email']); ?>
                </div>
                
                <div class="credential">
                    <strong>ID Unique :</strong><br>
                    <?php echo htmlspecialchars($_SESSION['new_id']); ?>
                </div>
                
                <div class="credential">
                    <strong>Token Personnel :</strong><br>
                    <?php echo htmlspecialchars($_SESSION['new_token']); ?>
                </div>
                
                <p style="margin-top: 15px; color: #c05621;">
                    ⚠️ <strong>Important :</strong> Notez ces informations dans un endroit sûr. Vous en aurez besoin pour vous connecter.
                </p>
            </div>
            
            <a href="auth.php" class="btn-submit" style="text-decoration: none; display: block; text-align: center;">
                Se connecter maintenant
            </a>
        <?php else: ?>
            <?php if ($error): ?>
                <div class="error"><?php echo $error; ?></div>
            <?php endif; ?>
            
            <div class="info-box">
                ℹ️ Votre email doit être au format <strong>prenom.nom@<?php echo SSO_DOMAIN; ?></strong>
            </div>
            
            <form method="POST">
                <div class="form-group">
                    <label>Prénom</label>
                    <input type="text" name="prenom" required>
                </div>
                
                <div class="form-group">
                    <label>Nom</label>
                    <input type="text" name="nom" required>
                </div>
                
                <div class="form-group">
                    <label>Email @<?php echo SSO_DOMAIN; ?></label>
                    <input type="email" name="email" placeholder="prenom.nom@<?php echo SSO_DOMAIN; ?>" required>
                </div>
                
                <button type="submit" name="register" class="btn-submit">
                    Créer mon compte
                </button>
            </form>
            
            <p style="text-align: center; margin-top: 20px; color: #718096;">
                Déjà inscrit ? <a href="auth.php" style="color: #667eea; text-decoration: none;">Se connecter</a>
            </p>
        <?php endif; ?>
    </div>
</body>
</html>
